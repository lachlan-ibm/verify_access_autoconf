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
