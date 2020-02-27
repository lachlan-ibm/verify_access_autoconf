from .configure import ISVA_Configurator as Configurator
from .appliance.configure_appliance import Appliance_Configurator
from .docker.configure_docker import Docker_Configurator
from .access_control.configure_aac import AAC_Configurator
from .federation.configure_fed import FED_Configurator
from .webseal.configure_webseal import WEB_Configurator

configurator = Configurator()
app = Appliance_Configurator()
docker = Docker_Configurator()
aac = AAC_Configurator()
fed = FED_Configurator()
web = WEB_Configurator()
