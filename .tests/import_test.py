#!/bin/python

def import_test():
    try:
        import ivsa_configurator
        assert isva_configurator.configurator != None
        assert isva_configurator.appliance != None
        assert isva_configurator.docker != None
        assert isva_configurator.appliance != None
        assert isva_configurator.web != None
        assert isva_configurator.aac != None
        assert isva_configurator.fed != None
    except:
        assert False, "Import test failed"
