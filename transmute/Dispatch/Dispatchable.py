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
   
   def __iter__(self):
      if hasattr(self, 'children'):
         for c in self.children:
            yield c
      raise StopIteration("No children")