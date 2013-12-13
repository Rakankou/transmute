from abc import ABCMeta, abstractmethod

__all__ = ["Dispatchable", "DispatchError"]

class DispatchError(ValueError):
   pass

class Dispatchable(metaclass = ABCMeta):
   @staticmethod
   @abstractmethod
   def tag():
      return ''
   
   def getTag(self):
      return type(self).tag()