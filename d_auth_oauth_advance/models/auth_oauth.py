from odoo import fields, models


class AuthOAuthProvider(models.Model):

    _inherit = 'auth.oauth.provider'

    client_secret = fields.Char(string='Client Secret')
