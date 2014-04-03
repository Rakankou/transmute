##
# @file transmute/Dispatch/Dispatcher.py
# @brief Contains the main dispatch director
# @defgroup plugins
# @{
#  @page Plugins
#  Transmute is based on a plugin architecture. This is implemented by the 
#  @ref transmute.Dispatch.Dispatcher.Dispatcher "Dispatcher", and accomplished
#  by the importlib module. The @ref transmute.plugins.base "base" plugin provides the
#  base set of elements understood by transmute. The first output plugin is the
#  @ref transmute.plugins.wireshark "wireshark" plugin, which also serves as a sample
#  from which to develop further plugins.
# @}
import os
import logging
import importlib

##
# @brief All of the items exported by this module
__all__ = ["Dispatcher", "DispatchError"]
##
# @brief The module's top-level logger
_logger = logging.getLogger('transmute.Dispatch')

##
# @class Dispatcher
# @brief Directs the dispatch process for fully-parsed elements.
class Dispatcher(object):
   ##
   # @name __init__
   # @brief Load modules for dispatch
   # @param package [in] The directory from which to load modules
   # @param relative_to [in] The path in which package resides
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
   
   ##
   # @name register_all
   # @brief Register all of the loaded modules.
   def register_all(self, args_parser, xml_parser):
      for mod in self.modules:
         mod.register(args_parser, xml_parser)
   
   ##
   # @name push
   # @brief Push a @ref transmute.Dispatch.Dispatchable.Dispatchable "Dispatchable" to every loaded module.
   def push(self, dispatchable_obj):
      for mod in self.modules:
         mod.dispatch(dispatchable_obj)
   
   ##
   # @name getModules
   # @brief Get a list of all of the loaded modules.
   def getModules(self):
      #a copy of self.modules, to prevent accidental changes to the list
      return [mod for mod in self.modules]
