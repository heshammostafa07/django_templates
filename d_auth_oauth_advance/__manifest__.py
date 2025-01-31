{
    'name': "OAuth2 Authentication Advance",

    'summary': """
Base module add a field call client_secret for other module which need that field to expand and some other ultilities.
""",

    'description': """
Key Features
============

- This module add a field call client_secret for other module which need that field to expand and some other ultilities.

Editions Supported
==================
1. Community Edition
2. Enterprise Edition

    """,

    'author': "ndd",
    'website': "https://duong-odoo-apps.odoo.com",
    'support': "daiduongnguyen2709@gmail.com",
    'category': 'Extra Tools',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': ['auth_oauth'],

    # always loaded
    'data': [
        'views/auth_oauth_views.xml',
    ],

    'images': ['static/description/main_screenshot.png'],
    'installable': True,
    'application': False,
    'auto_install': True,
    'price': 0.0,
    'currency': 'EUR',
    'license': 'OPL-1',
}
