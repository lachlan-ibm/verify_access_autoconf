from .configure import ISVA_Configurator as Configurator
from .appliance import Appliance_Configurator
from .container import Docker_Configurator
from .access_control import AAC_Configurator
from .federation import FED_Configurator
from .webseal import WEB_Configurator

"""
:var configurator: The configurator object which should be the object to the automated configuration process.

To start the automated configuration. use the  :func:`~Configurator.configure` method.
"""
configurator = Configurator()

"""
:var app: Can be used to configure appliance deployments system properties.
"""
app = Appliance_Configurator()

"""
:var docker: Can be used to configure container deployment system properties.
"""
cont = Docker_Configurator()

"""
:var aac: Can be used to configure the Advanced Access Control module.
"""
aac = AAC_Configurator()

"""
:var fed: Can be used to configure Federation module.
"""
fed = FED_Configurator()

"""
:var web: can be used to configure the WebSEAL Reverse Proxy module.
"""
web = WEB_Configurator()
