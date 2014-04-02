##
# @file transmute/Dispatch/Dispatchable.py
# @brief Contains the base class for items that can be used with the @ref transmute.Dispatch.Dispatcher.Dispatcher "Dispatcher"
#
from abc import ABCMeta, abstractmethod

__all__ = ["Dispatchable", "DispatchError"]

##
# @class DispatchError
# @brief A base error class representing an error during the dispatch process.
class DispatchError(ValueError):
   pass

##
# @class Dispatchable
# @brief Base class for elements that can be dispatched
class Dispatchable(metaclass = ABCMeta):
   @staticmethod
   @abstractmethod
   ##
   # @name tag
   # @brief Yield the XML tag of this element type.
   def tag():
      return ''
   
   ##
   # @name getTag
   # @brief Yield the XML tag of this element instance.
   def getTag(self):
      return type(self).tag()
   
   ##
   # @name __iter__
   # @brief Yield each child element in this instance.
   def __iter__(self):
      if hasattr(self, 'children'):
         for c in self.children:
            yield c
      raise StopIteration("No children")