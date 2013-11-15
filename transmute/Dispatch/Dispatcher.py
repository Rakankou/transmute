import os
import logging
import importlib

__all__ = ["Dispatcher", "DispatchError"]
_logger = logging.getLogger('transmute.Dispatch')

class Dispatcher(object):
   def __init__(self, package, relative_to='transmute'):
      self.log = logging.getLogger('transmute.Dispatch.Dispatcher')
      self.log.debug("Setting up Dispatcher for {}".format(os.path.join(relative_to, package)))
      pkg = ['transmute'] + package.split(os.path.sep)
      self._pmod   = [importlib.import_module(''.join(['.', pkg[pivot]]), '.'.join(pkg[:pivot])) for pivot in range(1, len(pkg))]
      self.log.debug("Parent modules: {}".format([pmod.__name__ for pmod in self._pmod]))
      self.modules = [importlib.import_module(''.join(['.', mod[:-3]]), '.'.join(pkg)) for mod in (
                           f for f in os.listdir(os.path.join('transmute', package)) if (f.endswith('.py') and f != '__init__.py'))
                     ]
      self.log.debug("Loaded modules: {}".format([mod.__name__ for mod in self.modules]))
   
   def register_all(self, args_parser, xml_parser):
      for mod in self.modules:
         mod.register(args_parser, xml_parser)
   
   def push(self, dispatchable_obj):
      for mod in self.modules:
         mod.dispatch(dispatchable_obj)
   
   def getModules(self):
      #a copy of self.modules, to prevent accidental changes to the list
      return [mod for mod in self.modules]
