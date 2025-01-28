import datetime
import json
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from kubernetes import client, config
import base64
import logging
from textwrap import dedent
from django.shortcuts import render, redirect
import requests


logger = logging.getLogger(__name__)



def load_kubernetes_config():
    """Configure Kubernetes client with TLS verification disabled"""
    config.load_kube_config()
    configuration = client.Configuration.get_default_copy()
    configuration.verify_ssl = False
    configuration.debug = True
    client.Configuration.set_default(configuration)

def create_namespace(namespace_name):
    v1 = client.CoreV1Api()
    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name,
            labels={
                "app": namespace_name,
                "customer": namespace_name,
                "managed-by": "django-odoo-saas",
                "service-type": "odoo"
            }
        )
    )
    try:
        v1.create_namespace(namespace)
        print(f"Namespace '{namespace_name}' created.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"Namespace '{namespace_name}' already exists.")
        else:
            raise


def create_configmap(namespace, name, branch):
    name = f"{namespace}-{branch}-configmap"
    db_user = f"{namespace}_{branch}"
    
    # Get the secrets that we need
    v1 = client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(f"{namespace}-{branch}-secret", namespace)
        user_password = base64.b64decode(secret.data['USER_PASSWORD']).decode('utf-8')
        admin_passwd = base64.b64decode(secret.data['ADMIN_PASSWD']).decode('utf-8')
    except client.exceptions.ApiException as e:
        print(f"Error reading secret: {e}")
        raise
        
    config_map = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        data={
            "odoo.conf": dedent(f'''
                [options]
                addons_path = /mnt/extra-addons/addons,/mnt/extra-addons/ent
                data_dir = /mnt/extra-addons/data
                db_host = postgres-svc.db.svc.cluster.local
                db_port = 5432
                db_user = {db_user}
                db_password = {user_password}
                db_maxconn = 64
                admin_passwd = {admin_passwd}
                limit_memory_hard = 2684354560
                limit_memory_soft = 2147483648
                limit_request = 8192
                limit_time_cpu = 600
                limit_time_real = 1200
                max_cron_threads = 2
                workers = 3
                proxy_mode = True
                log_level = info
                log_handler = :INFO
                csv_internal_sep = ,
                ''').strip()
        },
    )
    
    # Log the configuration being created (without sensitive data)
    print(f"Creating ConfigMap for database user: {db_user}")
    
    try:
        v1.create_namespaced_config_map(namespace=namespace, body=config_map)
        print(f"ConfigMap '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"ConfigMap '{name}' already exists in namespace '{namespace}'.")
        else:
            raise



def create_persistent_volume_claim(namespace, branch):
    name = f"{namespace}-{branch}-pvc"
    v1 = client.CoreV1Api()
    pvc = client.V1PersistentVolumeClaim(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1PersistentVolumeClaimSpec(
            storage_class_name="longhorn",
            access_modes=["ReadWriteOnce"],
            resources=client.V1ResourceRequirements(requests={"storage": "5Gi"})
        )
    )
    try:
        v1.create_namespaced_persistent_volume_claim(namespace=namespace, body=pvc)
        print(f"PersistentVolumeClaim '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"PersistentVolumeClaim '{name}' already exists in namespace '{namespace}'.")
        else:
            raise


def create_docker_secret(namespace, branch):
    name = f"{namespace}-{branch}-docker-secret"
    v1 = client.CoreV1Api()
    docker_config = {
        "auths": {
            "dockerregistry.erpunity.com": {
                "username": "admin",
                "password": "TicoTico@#2024",
                "email": "h@gmail.com",
                "auth": base64.b64encode(b"admin:TicoTico@#2024").decode("utf-8"),
            }
        }
    }
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        type="kubernetes.io/dockerconfigjson",
        data={".dockerconfigjson": base64.b64encode(json.dumps(docker_config).encode()).decode("utf-8")},
    )
    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret)
        print(f"Docker Secret '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"Docker Secret '{name}' already exists in namespace '{namespace}'.")
        else:
            raise


def create_opaque_secret(namespace, branch):
    name = f"{namespace}-{branch}-secret"
    v1 = client.CoreV1Api()
    secret_data = {
        "PGPASSWORD": base64.b64encode(b"odoo123").decode("utf-8"),
        "USER_PASSWORD": base64.b64encode(b"user_password_value").decode("utf-8"),
        "ADMIN_PASSWD": base64.b64encode(b"OdooTec@#2024").decode("utf-8"),
    }
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        type="Opaque",
        data=secret_data,
    )
    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret)
        print(f"Opaque Secret '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"Opaque Secret '{name}' already exists in namespace '{namespace}'.")
        else:
            raise


def create_service(namespace, branch):
    name = f"{namespace}-{branch}-svc".replace("_", "-")
    v1 = client.CoreV1Api()
    service = client.V1Service(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        spec=client.V1ServiceSpec(
            selector={"app": f"{namespace}-{branch}".replace("_", "-")},
            ports=[
                client.V1ServicePort(name="web", port=8069, target_port=8069),
                client.V1ServicePort(name="websocket", port=8072, target_port=8072),
            ],
            type="ClusterIP",
        ),
    )
    try:
        v1.create_namespaced_service(namespace=namespace, body=service)
        print(f"Service '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"Service '{name}' already exists in namespace '{namespace}'.")
        else:
            raise


def create_tls_secret(namespace, name):
    v1 = client.CoreV1Api()
    secret_data = {
        "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUUrRENDQStDZ0F3SUJBZ0lTQkJWMmdtTkMrbDIyeklvaE82eGtZQzV5TUEwR0NTcUdTSWIzRFFFQkN3VUEKTURNeEN6QUpCZ05WQkFZVEFsVlRNUll3RkFZRFZRUUtFdzFNWlhRbmN5QkZibU55ZVhCME1Rd3dDZ1lEVlFRRApFd05TTVRFd0hoY05NalV3TVRJek1EY3pPVEk0V2hjTk1qVXdOREl6TURjek9USTNXakFYTVJVd0V3WURWUVFECkV3eGxjbkIxYm1sMGVTNWpiMjB3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ1MKMXJuV3hXbUo1ekZodkljaUp3T3pxb3J2b0M2d2czUEJxL0o3SG1UQVVZM3dTY3l1ZmdOV3dFc1o2anptaEpjOAovVGhkbHNoTFNQSnlSWDBaL0NReWVEL0EzUlpnS2psU1R2SG9oYzdRdU1zdkpIWFlabUl6V2RJa2RNcTdjcVV4CmRlNzBHK2dnSy95bFQwUDRGdWlDTitiaS9UYzJyTit3T29QMmxjS0V0R1dhamU1Q1R4Nk4rWFNqRnNCM29nRHcKc2ZoOERlTTBxVHVzTk9zK3pibXEzeC81cDYwVlA4R3l6S3BJdVdGMUFrbndCYXJLL0tJaWlMSkN4NnFEM1FLSgpWS1UxbytXbDluQ082ZzUyejMvK0FlcUNsQk1kb1I5UDVHOHJPK2ZWbnorMlhPa2wvWVc5ZlpQOW5GblB4TWp6CnF3QWdwcTNaczhqRmROU3N3eit4QWdNQkFBR2pnZ0lnTUlJQ0hEQU9CZ05WSFE4QkFmOEVCQU1DQmFBd0hRWUQKVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUF3R0ExVWRFd0VCL3dRQ01BQXdIUVlEVlIwTwpCQllFRkZwcW0wSFZIWGJpOXUxL1BoRkZtSjVlMEVJbk1COEdBMVVkSXdRWU1CYUFGTVhQUnFUcTlNUEFlbXlWCnhDMndYcEl2SnVPNU1GY0dDQ3NHQVFVRkJ3RUJCRXN3U1RBaUJnZ3JCZ0VGQlFjd0FZWVdhSFIwY0RvdkwzSXgKTVM1dkxteGxibU55TG05eVp6QWpCZ2dyQmdFRkJRY3dBb1lYYUhSMGNEb3ZMM0l4TVM1cExteGxibU55TG05eQpaeTh3SndZRFZSMFJCQ0F3SG9JT0tpNWxjbkIxYm1sMGVTNWpiMjJDREdWeWNIVnVhWFI1TG1OdmJUQVRCZ05WCkhTQUVEREFLTUFnR0JtZUJEQUVDQVRDQ0FRUUdDaXNHQVFRQjFua0NCQUlFZ2ZVRWdmSUE4QUIyQU16N0QycUYKY1FsbC9wV2JVODdwc253aTZZVmNEWmVOdHFsK1ZNRCtUQTJ3QUFBQmxKSlBuZEVBQUFRREFFY3dSUUlnQ2syYQpFdXpSaUM0UnlxL3pIYWZlMUNFY1VrM3I3aXNrajlXa1o0R3RmOWdDSVFDRWh2TkVtS1ZsSmtyZHRLOC80TmR1CldqWFZLMmYzYWNRWjNEMHI5SFFjSHdCMkFNOFJWdTdWTG55djg0ZGIyV2t1bStrYWNXZEtzQmZzckFIU1czZk8KekRzSUFBQUJsSkpQbmZNQUFBUURBRWN3UlFJZ0xyYTZYRzl6R25HcjkyNGozOWsxbmphSXUzUno4aTgxVDdNQQpoQmt5OFZVQ0lRRDFUSnpPZDJNc0NTZVFOMndLR29xNkZxNVd1R1NiL205dXo5RHQ3L3NvYnpBTkJna3Foa2lHCjl3MEJBUXNGQUFPQ0FRRUFGZ09VM3JvaGFDWnhRbnR0OHk5akFBNGFGWlVMd1JkZVFtNDMwMFg1UjJicXZ6b3YKdDlrRHEwbzV2TytQN1VNMEx3dHgxUXlGOFg0SHNDNTRiVEZ5Vjl0UDYxSXNrK2VDeGRYa0hnZVEwMVcyUHl4dQpOMjd1UmlXR3IxQm9xa0xoREFSVVpFMDVVZDIwU0ZWNXk4RHZLS2ZRRFhRMzhwMHRLQ1A2djRvb2NhS1Y4TkhxCnhUdHQ1UmJBL015d0pRU3VMT0lSNGxpcERHZ0dBRnlPRmtHWVNkVkJKMVRhZ0JXMnRlb0hBQ2VCckNNaVB1L1QKeWUzQW5ldm02VGk2YUI3YzcyVDlraTlvSmhhcTVSMk1wcE5SZ3N0VEZid2t3NGhzOXkrUDZKMVN0V1BRWVh0YQp4NjM5dngvRnpMUW5KSThtaVF5TUkxWjBSYXpFTTJyWlBEQVhOUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZCakNDQXU2Z0F3SUJBZ0lSQUlwOVBoUFdMekR2STRhOUtRZHJOUGd3RFFZSktvWklodmNOQVFFTEJRQXcKVHpFTE1Ba0dBMVVFQmhNQ1ZWTXhLVEFuQmdOVkJBb1RJRWx1ZEdWeWJtVjBJRk5sWTNWeWFYUjVJRkpsYzJWaApjbU5vSUVkeWIzVndNUlV3RXdZRFZRUURFd3hKVTFKSElGSnZiM1FnV0RFd0hoY05NalF3TXpFek1EQXdNREF3CldoY05NamN3TXpFeU1qTTFPVFU1V2pBek1Rc3dDUVlEVlFRR0V3SlZVekVXTUJRR0ExVUVDaE1OVEdWMEozTWcKUlc1amNubHdkREVNTUFvR0ExVUVBeE1EVWpFeE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQgpDZ0tDQVFFQXVvZThYQnNBT2N2S0NzM1VaeEQ1QVR5bFRxVmh5eWJLVXZzVkFiZTVLUFVvSHUwbnN5UVlPV2NKCkRBanM0RHF3TzNjT3ZmUGxPVlJCREU2dVFkYVpkTjVSMis5Ny8xaTlxTGNUOXQ0eDFmSnl5WEpxQzROMGxaeEcKQUdRVW1mT3gyU0xaemFpU3Fod21lai8rNzFnRmV3aVZnZHR4RDQ3NzR6RUp1d20rVUUxZmo1RjJQVnFkbm9QeQo2Y1JtcytFR1prTklHSUJsb0RjWW1wdUVNcGV4c3IzRStCVUFuU2VJKytKakY1WnNteWRuUzhUYktGNXB3bm53ClNWemdKRkRoeEx5aEJheDdRRzBBdE1KQlA2ZFl1Qy9GWEp1bHV3bWU4Zjdyc0lVNS9hZ0s3MFhFZU90bEtzTFAKWHp6ZTQxeE5HL2NMSnl1cUMwSjNVMDk1YWgySDJRSURBUUFCbzRINE1JSDFNQTRHQTFVZER3RUIvd1FFQXdJQgpoakFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVIQXdFd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93SUJBREFkQmdOVkhRNEVGZ1FVeGM5R3BPcjB3OEI2YkpYRUxiQmVraThtNDdrd0h3WURWUjBqQkJnd0ZvQVUKZWJSWjVudTI1ZVFCYzRBSWlNZ2FXUGJwbTI0d01nWUlLd1lCQlFVSEFRRUVKakFrTUNJR0NDc0dBUVVGQnpBQwpoaFpvZEhSd09pOHZlREV1YVM1c1pXNWpjaTV2Y21jdk1CTUdBMVVkSUFRTU1Bb3dDQVlHWjRFTUFRSUJNQ2NHCkExVWRId1FnTUI0d0hLQWFvQmlHRm1oMGRIQTZMeTk0TVM1akxteGxibU55TG05eVp5OHdEUVlKS29aSWh2Y04KQVFFTEJRQURnZ0lCQUU3aWlWMEtBeHlRT05EMUgvbHhYUGpEajdJM2lIcHZzQ1VmN2I2MzJJWUdqdWtKaE0xeQp2NEh6L01yUFUwanR2ZlpwUXRTbEVUNDF5Qk95a2gwRlgrb3UxTmo0U2NPdDlabVduTzhtMk9HMEpBdElJRTM4CjAxUzBxY1loeU9FMkcvOTNaQ2tYdWZCTDcxM3F6WG5RdjVDL3ZpT3lrTnBLcVVneGRLbEVDK0hpOWkyRGNhUjEKZTlLVXdRVVpSaHk1ai9QRWRFZ2xLZzNsOWR0RDR0dVRtN2tadEI4djMyb09qekhUWXcrN0tkemRaaXcvc0J0bgpVZmhCUE9STnVheTRwSnhtWS9XcmhTTWR6Rk8ycTNHdTNNVUJjZG8yN2dvWUtqTDlDVEY4ai9aejU1eWN0VW9WCmFuZUNXcy9halVYK0h5cGtCVEErYzhMR0RMbldPMk5LcTBZRC9wbkFSa0FuWUdQZlVEb0hSOWdWU3AvcVJ4K1oKV2doaURMWnNNd2hOMXpqdFNDMHVCV2l1Z0YzdlROellJRUZmYVBHN1dzM2pEckFNTVllYlE5NUpRK0hJQkQvUgpQQnVIUlRCcHFLbHlEbmtTSERIWVBpTlgzYWRQb1BBY2dkRjNIMi9XMHJtb3N3TVdnVGxMbjFXdTBtcmtzNy9xCnBkV2ZTNlBKMWp0eTgwcjJWS3NNL0RqM1lJRGZialhLZGFGVTVDKzhiaGZKR3FVM3RhS2F1dXowd0hWR1QzZW8KNkZsV2tXWXRidDRwZ2RhbWx3VmVaRVcrTE03cVpFSkVzTU5QcmZDMDNBUEttWnNKZ3BXQ0RXT0tadmtaY3ZqVgp1WWtRNG9tWUNUWDVvaHkra25NamRPbWRIOWM3U3BxRVdCREM4NmZpTmV4K08wWE9NRVpTYThEQQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
        "tls.key" : "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBa3RhNTFzVnBpZWN4WWJ5SElpY0RzNnFLNzZBdXNJTnp3YXZ5ZXg1a3dGR044RW5NCnJuNERWc0JMR2VvODVvU1hQUDA0WFpiSVMwanlja1Y5R2Z3a01uZy93TjBXWUNvNVVrN3g2SVhPMExqTEx5UjEKMkdaaU0xblNKSFRLdTNLbE1YWHU5QnZvSUN2OHBVOUQrQmJvZ2pmbTR2MDNOcXpmc0RxRDlwWENoTFJsbW8zdQpRazhlamZsMG94YkFkNklBOExINGZBM2pOS2s3ckRUclBzMjVxdDhmK2FldEZUL0Jzc3lxU0xsaGRRSko4QVdxCnl2eWlJb2l5UXNlcWc5MENpVlNsTmFQbHBmWndqdW9PZHM5Ly9nSHFncFFUSGFFZlQrUnZLenZuMVo4L3RsenAKSmYyRnZYMlQvWnhaejhUSTg2c0FJS2F0MmJQSXhYVFVyTU0vc1FJREFRQUJBb0lCQUJqNUgvNGc4UVFkSjg3aAppM0lKaEoybjRaMURkdTFhVGZPZ1ZNc1Byajd2SDk3QURtbVcwT2FPS2Jlc21OTHp0ZTBQZStpZTNrMi9pRXhhCitSM1VQaXUvTzhpSFVXamxoWDQwSXZ4UzFZdTJBZ2h3Z1FKZTExQzRjLzd6Umc5L1BnMGRhNWhrcnFQYUYwdmUKSVVjdVRqam5YUU01NFl3UTlySTRJWDFzbHZxT21jMWFEUXRWNngwN05zdjA1U3puUUFNeGVxRVVLOW4rQ1M5VApNOGdocEtJUlRqb0ZpeVljeGN2UWRxNGp1NmU2RnNBbldGb3NaUXU5anIveXdMYW1Nd3lraFU5aGdmczRKbFJlCjcvc01tb0hHdHVQTEYzdVpwM3FZSUR5U0FsUGxZZU9Tdzd1aVlEd3owaXlWOW9lTEtVZ0x2QXliUC9SNnIwbmEKN3JIRGhva0NnWUVBdzhOb2xBSUJWVEE4ak1ndUtheU5ua3hRNVFSaWlZalMzU0JSMFduZmFSdGNwV0dLU3RQcwo0Y25NM1RRWlQ0OHNhZGkySlhzQzlEemhOa2xvUlNXckxheDNJRkhtcFFQQStGSXlkOFJ6TDFKdkFEZ0VCeWNZCmRUU1pJYXYvak5YbE1ENWFoTVJRdUd6endiZ3U4bW5UMFp1NFI0WTg3Wm9zSDNzajZmUS9scnNDZ1lFQXdBVnoKMlFDRjNTTllsTktDWnVNTVh4aEpiRmNnNE9jQlZwRjdmWWNWUUNzTXNWMTF5SVFkdXFTTWlYTURob3FGWW9zRgpSdVdTS0hOYUtjS3NzTTdtYVhJVEZNOEE0bkxZbVJHODlIOXpTdzZzMm9ZTXgyazFsbnlBMkVEQjZvRWlibkVtCllERTExTlcwY095SjI4UExqamI5SlhhTnFPdEU0RU5VS21yc2VvTUNnWUVBZ05Cd1hCUUZ0SHlORzBZTnVqWmsKNmFqbUFneWtta09DSFNkTEx6VXZZUVkwTEU3R3BQNVdmU3hBdGIyMmVmZUlEZzRmclFJSXE1WHp5N2o1OTZZVgp3WFFlM3hHRlowZlZEcEZuekE5a2k5citWM0tFbEFCUnc2M2NwWjk4Qkx3cWwxZ3dUL1N0K08wWWFIdzl5QjJDCjJBWlRlQjBJc29Ba1VJTEMyd3R4WEVrQ2dZRUFzNnNtWjNBMjBPQ0d2TkZ2bEdkenB2THBtSWE1eTlZNkNVOGMKMWlwejl0T1JEOUFjS2g5OFZhd3JsMXhYZXliWGdZb0V5UDU3VUlBR2FEYXdNTXVYQ2lqanM3K3cyekdNZTBUKwpvV016ZEpKcHFCcHZrSkpmd3N3Q0h0WVEyNlF5bkZZaEN6WmdZU0lJc1BTU1ZXQVJjYU1BSUhLYVArakxURytUCkxCRlo3Wk1DZ1lCcDYwSXNYTEdMS0p3bVhZYnkzWUM4aFlkWldRNERqYzJUUXZkTG83R0lxWXg0cXo2Q1RxTisKVVdmMVRlRlF4ZTNDbWNHUjdHZWdQZm9NMk12VzFFbWlLSmJPWHRKUUFRMVUxWUlJNDlLeGRkNmRQTnRjUXdrNwpGbURHUDZlV1JGZHBXdzhVMk05cFpoSmRhOEtZV2s0WHRvTEpxOXo2Z0NDUmd2Vnd3SkVJV1E9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="
    }
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        type="kubernetes.io/tls",
        data=secret_data
    )
    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret)
        print(f"TLS Secret '{name}' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"TLS Secret '{name}' already exists in namespace '{namespace}'.")
        else:
            print(f"Failed to create TLS Secret: {e}")
            raise


def create_ingress(namespace, branch):
    sanitized_name = f"{namespace}-{branch}".replace("_", "-")
    v1 = client.NetworkingV1Api()
    ingress = client.V1Ingress(
        metadata=client.V1ObjectMeta(
            name=sanitized_name + "-ing",
            namespace=namespace,
            annotations={
                "nginx.ingress.kubernetes.io/proxy-read-timeout": "720s",
                "nginx.ingress.kubernetes.io/proxy-send-timeout": "720s",
                "nginx.ingress.kubernetes.io/proxy-connect-timeout": "720s",
                "nginx.ingress.kubernetes.io/proxy-body-size": "500m",
                "nginx.ingress.kubernetes.io/proxy-buffer-size": "32k",
                "nginx.ingress.kubernetes.io/proxy-http-version": "1.1",
                "nginx.ingress.kubernetes.io/connection-upgrade": "true",
                "nginx.ingress.kubernetes.io/upgrade": "websocket",
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
            },
        ),
        spec=client.V1IngressSpec(
            ingress_class_name="nginx",
            tls=[
                client.V1IngressTLS(
                    hosts=[f"{sanitized_name}.erpunity.com"],
                    secret_name=f"{namespace}-tls-secret",
                )
            ],
            rules=[
                client.V1IngressRule(
                    host=f"{sanitized_name}.erpunity.com",
                    http=client.V1HTTPIngressRuleValue(
                        paths=[
                            client.V1HTTPIngressPath(
                                path="/",
                                path_type="Prefix",
                                backend=client.V1IngressBackend(
                                    service=client.V1IngressServiceBackend(
                                        name=f"{namespace}-{branch}-svc".replace("_", "-"),
                                        port=client.V1ServiceBackendPort(number=8069),
                                    )
                                ),
                            ),
                            client.V1HTTPIngressPath(
                                path="/websocket",
                                path_type="Prefix",
                                backend=client.V1IngressBackend(
                                    service=client.V1IngressServiceBackend(
                                        name=f"{namespace}-{branch}-svc".replace("_", "-"),
                                        port=client.V1ServiceBackendPort(number=8072),
                                    )
                                ),
                            ),
                        ]
                    ),
                )
            ],
        ),
    )
    try:
        v1.create_namespaced_ingress(namespace=namespace, body=ingress)
        print(f"Ingress '{sanitized_name}-ing' created in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"Ingress '{sanitized_name}-ing' already exists in namespace '{namespace}'.")
        else:
            print(f"Failed to create Ingress: {e}")
            raise


def create_deployment(namespace, branch):
    name = f"{namespace}-{branch}"
    apps_v1 = client.AppsV1Api()
    
    restart_annotation = {"restart-timestamp": datetime.datetime.utcnow().isoformat()}

    deployment = client.V1Deployment(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            annotations=restart_annotation,
            labels={
                "app": name,
                "environment": branch,
                "customer": namespace,
                "managed-by": "django-odoo-saas",
                "service-type": "odoo"
            }
        ),
        spec=client.V1DeploymentSpec(
            replicas=1,
            selector=client.V1LabelSelector(
                match_labels={"app": name}
            ),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"app": name},
                    annotations=restart_annotation,
                ),
                spec=client.V1PodSpec(
                    init_containers=[
                        client.V1Container(
                            name=f"{name}-db-user",
                            image="dockerregistry.erpunity.com/odooerp/odoo-ent-18:latest",
                            env=[
                                client.V1EnvVar(name="LANG", value="en_US.UTF-8"),
                                client.V1EnvVar(name="LANGUAGE", value="en_US:en"),
                                client.V1EnvVar(name="LC_ALL", value="en_US.UTF-8"),
                                client.V1EnvVar(
                                    name="PGPASSWORD",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name=f"{name}-secret", key="PGPASSWORD"
                                        )
                                    ),
                                ),
                                client.V1EnvVar(
                                    name="USER_PASSWORD",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name=f"{name}-secret", key="USER_PASSWORD"
                                        )
                                    ),
                                ),
                            ],
                            command=["/bin/bash", "-c"],
                            args=[f"""
                                    until PGPASSWORD=$PGPASSWORD psql -h postgres-svc.db.svc.cluster.local -U admin -d postgres -c '\l' > /dev/null 2>&1; do
                                        echo "Connection attempt at $(date)"
                                        echo "Retrying in 5 seconds..."
                                        sleep 5
                                    done

                                    echo "Successfully connected to PostgreSQL"

                                    PGPASSWORD=$PGPASSWORD psql -h postgres-svc.db.svc.cluster.local -U admin -d postgres -c "
                                    DO
                                    \\$\\$
                                        BEGIN
                                        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{namespace}_{branch}') THEN
                                            CREATE ROLE {namespace}_{branch} WITH LOGIN CREATEDB PASSWORD '$USER_PASSWORD';
                                            GRANT ALL PRIVILEGES ON DATABASE postgres TO {namespace}_{branch};
                                            RAISE NOTICE 'Created new role: {namespace}_{branch}';
                                        ELSE
                                            ALTER ROLE {namespace}_{branch} WITH LOGIN CREATEDB PASSWORD '$USER_PASSWORD';
                                            GRANT ALL PRIVILEGES ON DATABASE postgres TO {namespace}_{branch};
                                            RAISE NOTICE 'Updated existing role: {namespace}_{branch}';
                                        END IF;
                                        END;
                                    \\$\\$;
                                    "
                            """],
                        ),
                        client.V1Container(
                            name=f"{name}-permissions",
                            image="alpine",
                            command=["sh", "-c"],
                            args=["chown -R 100:101 /mnt/extra-addons/data"],
                            volume_mounts=[
                                client.V1VolumeMount(name="odoo-data", mount_path="/mnt/extra-addons/data")
                            ],
                            security_context=client.V1SecurityContext(
                                run_as_user=0
                            )
                        ),
						client.V1Container(
						   name=f"{name}-init-db",
						   image="dockerregistry.erpunity.com/odooerp/odoo-ent-18:latest",
						   env=[
							   client.V1EnvVar(name="USER_PASSWORD",
								   value_from=client.V1EnvVarSource(
									   secret_key_ref=client.V1SecretKeySelector(
										   name=f"{name}-secret", 
										   key="USER_PASSWORD"
									   )
								   )
							   )
						   ],
						   command=["/bin/bash", "-c"],
						   args=[f"/bin/odoo -d {namespace}_{branch} -u base --db_host postgres-svc.db.svc.cluster.local --db_port 5432 --db_user {namespace}_{branch} --db_password $USER_PASSWORD --stop-after-init"],
						   volume_mounts=[
							   client.V1VolumeMount(name="config", mount_path="/etc/odoo/odoo.conf", sub_path="odoo.conf"),
							   client.V1VolumeMount(name="odoo-data", mount_path="/mnt/extra-addons/data")
						   ]
					   )
                    ],
                    containers=[
                        client.V1Container(
                            name=f"{name}-app",
                            image="dockerregistry.erpunity.com/odooerp/odoo-ent-18:latest",
                            image_pull_policy="Always",
                            ports=[
                                client.V1ContainerPort(container_port=8069, name="web"),
                                client.V1ContainerPort(container_port=8072, name="websocket"),
                            ],
                            env=[
                                client.V1EnvVar(name="DB_HOST", value="postgres-svc.db.svc.cluster.local"),
                                client.V1EnvVar(name="DB_PORT", value="5432"),
                                client.V1EnvVar(name="DB_USER", value=f"{namespace}_{branch}"),
                                client.V1EnvVar(
                                    name="DB_PASSWORD",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name=f"{name}-secret", key="PGPASSWORD"
                                        )
                                    ),
                                ),
                                client.V1EnvVar(
                                    name="ADMIN_PASSWD",
                                    value_from=client.V1EnvVarSource(
                                        secret_key_ref=client.V1SecretKeySelector(
                                            name=f"{name}-secret", key="ADMIN_PASSWD"
                                        )
                                    ),
                                ),
                            ],
                            command=["/bin/bash", "-c"],
                            args=["odoo --config=/etc/odoo/odoo.conf"],
                            volume_mounts=[
                                client.V1VolumeMount(name="config", mount_path="/etc/odoo/odoo.conf", sub_path="odoo.conf"),
                                client.V1VolumeMount(name="odoo-data", mount_path="/mnt/extra-addons/data"),
                            ],
                        )
                    ],
                    volumes=[
                        client.V1Volume(
                            name="config",
                            config_map=client.V1ConfigMapVolumeSource(name=f"{name}-configmap"),
                        ),
                        client.V1Volume(
                            name="odoo-data",
                            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=f"{name}-pvc"
                            ),
                        ),
                    ],
                    image_pull_secrets=[
                        client.V1LocalObjectReference(name=f"{name}-docker-secret")
                    ],
                ),
            ),
        ),
    )

    try:
        # Delete existing deployment with wait
        try:
            existing_deployment = apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            if existing_deployment:
                print(f"Found existing Deployment '{name}', deleting it...")
                apps_v1.delete_namespaced_deployment(
                    name=name,
                    namespace=namespace,
                    propagation_policy="Foreground"
                )
                
                # Wait for deployment to be fully deleted
                max_retries = 30
                retry_interval = 2
                
                for i in range(max_retries):
                    try:
                        apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
                        print(f"Waiting for Deployment deletion... Attempt {i+1}/{max_retries}")
                        time.sleep(retry_interval)
                    except client.exceptions.ApiException as e:
                        if e.status == 404:
                            print("Deployment successfully deleted")
                            break
                    if i == max_retries - 1:
                        raise Exception("Timeout waiting for Deployment deletion")
                        
        except client.exceptions.ApiException as e:
            if e.status != 404:
                raise

        # Add extra delay after deletion
        time.sleep(5)
        
        print(f"Creating new Deployment '{name}'...")
        apps_v1.create_namespaced_deployment(namespace=namespace, body=deployment)
        print(f"Deployment '{name}' created successfully in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        print(f"Failed to manage Deployment '{name}': {e}")
        raise
    except Exception as e:
        print(f"Unexpected error managing Deployment '{name}': {e}")
        raise



@csrf_exempt
def github_webhook(request):
    if request.method == "POST":
        try:
            payload = json.loads(request.body)
            repo_url = payload["repository"]["html_url"]
            repo_name = repo_url.split("/")[-1]
            namespace = repo_name.split("-")[0]
            branch = payload["ref"].split("/")[-1]
            
            logger.info(f"Processing webhook for {namespace}/{branch}")
            load_kubernetes_config()
            v1 = client.CoreV1Api()
            apps_v1 = client.AppsV1Api()
            deployment_name = f"{namespace}-{branch}"

            try:
                # Check namespace existence
                namespace_exists = False
                try:
                    v1.read_namespace(namespace)
                    namespace_exists = True
                except client.exceptions.ApiException as e:
                    if e.status != 404:
                        raise

                # Check deployment existence
                deployment_exists = False
                try:
                    apps_v1.read_namespaced_deployment(deployment_name, namespace)
                    deployment_exists = True
                except client.exceptions.ApiException as e:
                    if e.status != 404:
                        raise

                if namespace_exists and deployment_exists:
                    logger.info(f"Updating existing deployment for {branch}")
                    create_deployment(namespace, branch)
                else:
                    logger.info("Creating all resources")
                    create_namespace(namespace)
                    create_docker_secret(namespace, branch)
                    create_opaque_secret(namespace, branch)
                    create_configmap(namespace, namespace, branch)
                    create_persistent_volume_claim(namespace, branch)
                    create_tls_secret(namespace, f"{namespace}-tls-secret")
                    create_service(namespace, branch)
                    create_ingress(namespace, branch)
                    create_deployment(namespace, branch)

                return JsonResponse({"status": "success"})

            except Exception as e:
                logger.error(f"Error: {str(e)}", exc_info=True)
                return JsonResponse({"status": "error", "message": str(e)})

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Payload error: {e}")
            return JsonResponse({"status": "error", "message": str(e)})

    return JsonResponse({"status": "error", "message": "Invalid method"}, status=405)