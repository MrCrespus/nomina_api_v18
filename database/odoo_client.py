import xmlrpc.client
import ssl
from config import Config


class OdooClient:
    def __init__(self, url=None, db=None, username=None, password=None):
        self.url = url or Config.ODOO_URL
        self.db = db or Config.ODOO_DB
        self.username = username or Config.ODOO_USERNAME
        self.password = password or Config.ODOO_PASSWORD
        self.uid = None
        self.models = None
        self._connect()

    def _connect(self):
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context

        common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common')
        self.uid = common.authenticate(
            self.db, self.username, self.password, {})
        self.models = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/object')

        if not self.uid:
            raise Exception(
                "Error de autenticación: Verifica tus credenciales.")
        print(f"Conectado a Odoo (UID: {self.uid})")

    def execute(self, model, method, *args, **kwargs):
        return self.models.execute_kw(
            self.db, self.uid, self.password,
            model, method, list(args), kwargs
        )
