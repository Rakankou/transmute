##
# @file transmute/Parsing/Parsable.py
# @brief Contains base classes representing parsable elements
#
from abc import ABCMeta, abstractmethod

##
# @brief All of the items exported by this module
__all__ = ["Parsable"]

##
# @name Parsable
# @brief The Interface to which all Parsables must conform.
#
class Parsable(metaclass = ABCMeta):
   ##
   # @brief Initializes the Parsable.
   def __init__(self):
      self.children = []
      self.parent   = None
   ##
   # @brief Gets the XML tag of the Parsable.
   # @return The XML tag of the Parsable.
   @staticmethod
   @abstractmethod
   def tag():
      return ''
   ##
   # @brief Gets the XML tag of the Parsable from an instance.
   # @return The XML tag of the Parsable instance.
   def getTag(self):
      return type(self).tag()
   ##
   # @name Start
   # @brief The method called when the START_ELEMENT event is encountered for this Parsable.
   # @param attrs [in] A dict of name:value pairs of the tag's attributes.
   # @param evt_stream [in,out] The DOMEventStream from which the node was pulled.
   # @param node [in,out] The node associated with the DOMEvent that spawned this call.
   # @param parser [in] The Parser instance responsible for generating evt_stream.
   # @return boolean True when the Parsable has consumed its own END_ELEMENT event (performed sub-parsing), else False.
   # @details Parsables that do not perform sub-parsing must ignore evt_stream and node.
   #          Parsables that do perform sub-parsing must consume their own END_ELEMENT event.
   #
   @abstractmethod
   def Start(self, attrs, evt_stream, node, parser):
      self.children = []
      self.parent   = None
      return False
   ##
   # @name End
   # @brief The method called when the END_ELEMENT event is encountered for this Parsable.
   #
   @abstractmethod
   def End(self):
      pass
   ##
   # @name Cdata
   # @brief The method called when the CHARACTERS event is encountered for this Parsable.
   # @param data [in] The text of the TextNode encountered.
   #
   @abstractmethod
   def Cdata(self, data):
      pass
   ##
   # @name Child
   # @brief The method called when the END_ELEMENT event is encountered for a child node of this Parsable.
   # @param child [in] The Parsable that has been consumed.
   # @details Classes inheriting this method must call super().Child() at the beginning of their Child() implementation.
   #
   @abstractmethod
   def Child(self, child):
      self.children.append(child)
   ##
   # @name Validate
   # @brief The method called when all parsing is complete.
   # @param parent [in] The parent Parsable of this Parsable, or None
   # @details Classes inheriting this method must call super().Validate() before the end of their Validate() implementation.
   #
   @abstractmethod
   def Validate(self, parent):
      self.parent = parent
      for c in self.children:
         c.Validate(self)
   