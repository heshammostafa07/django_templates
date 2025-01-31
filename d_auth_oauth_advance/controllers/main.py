from odoo import api, http, _
from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import OAuthLogin as oauth_login


class OAuthLogin(oauth_login):

    @http.route()
    def web_login(self, *args, **kw):
        response = super(OAuthLogin, self).web_login(*args, **kw)
        # TODO: Odoo auth_oauth module have check the case that credential may not valid but it is pretty general, we should fix this to odoo
        # if kw.get('oauth_error', False):
        #     if kw['oauth_error'] == '3':
        #         error = _('OAuth2: A user with the email that you use already exist so we can not create user with Oauth2 provider you have given')
        #         response.qcontext['error'] = error
        return response
