import logging


from odoo import api, fields, models, _
from odoo.http import request
from odoo.addons.auth_signup.models.res_partner import SignupError


_logger = logging.getLogger(__name__)

class ResUsers(models.Model):
    _inherit = 'res.users'

    @api.model
    def _signup_create_user(self, values):
        """ override to check if an email (login) already exist, show warning """
        if 'login' in values:
            user = self.sudo().search([('login', '=', values['login'])])
            if user:
                raise SignupError(_('OAuth2: A user with email %s already exist so we can not create user with Oauth2 provider you have given') % (values['login']))
        return super(ResUsers, self)._signup_create_user(values)
