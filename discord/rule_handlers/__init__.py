import os
import glob
import importlib
from rule_handlers.base_handler import BaseHandler

# Dynamically Import All Handlers
# Working directory is /var/ossec for Python scripts. Sys.path is /var/ossec/integrations
for submodule in [os.path.basename(f)[:-3] for f in glob.glob("integrations/rule_handlers/*.py") if not f.endswith("__init__.py")]:
    importlib.import_module("rule_handlers." + submodule)


def get_all_handlers():
    """ Returns all the classes that have subclassed the BaseHandler class. """
    return BaseHandler.__subclasses__()
