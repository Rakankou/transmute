##
# @file transmute/Parsing/Parser.py
# @brief Contains XML parsing-related base classes
#
import logging
from collections import UserList
from xml.dom     import pulldom
from .Parsable    import Parsable

__all__ = ["Parser", "ParseError"]

_logger = logging.getLogger('transmute.Parser')

##
# @name ParseError
# @brief The error emitted when parsing cannot be completed.
# @details Descends from ValueError
#
class ParseError(ValueError):
   pass

##
# @name ValidationError
# @brief The error emitted when validation cannot be completed.
# @details Descends from ValueError
#
class ValidationError(ValueError):
   pass

##
# @name Parser
# @brief Class encapsulating an XML parser.
class Parser(object):
   ##
   # @class Stack
   # @brief A simple stack class based on the UserList
   class Stack(UserList):
      ##
      # @name peek
      # @brief Peek at the top element of the stack.
      def peek(self):
         return self[-1]
      ##
      # @name push
      # @brief Push an element to the top of the stack
      # @param data [in] The element to push
      def push(self, data):
         self.append(data)
   
   ##
   # @name __init__
   # @brief Construct an empty Parser
   def __init__(self):
      self.__parsables = dict()
      self.log         = logging.getLogger('transmute.Parser.Parser')
      self.active      = False
      self.log.debug("Created Parser")
   
   ##
   # @name registerParsable
   # @brief Adds a Parsable type the the set of usable Parsables.
   # @param P The Parsable to add.
   #
   def registerParsable(self, P):
      self.__parsables[P.tag()] = P
      self.log.debug("Updated parsable in set: {}".format(P.tag()))
   
   ##
   # @name parse
   # @brief Parses a file (or stream) of xml.
   # @param file_or_stream [in] Stream-like object from which to pull XML.
   def parse(self, file_or_stream):
      self.log.debug("Setting up parser...")
      evt_stream = pulldom.parse(file_or_stream)
      self.log.debug("{}Parsing started with Parsable set {}".format('Sub-' if self.active else '', dict((p,self.__parsables[p].tag()) for p in self.__parsables)))
      for x in self._parse_evt_stream(evt_stream):
         yield x
   
   ##
   # @name parseString
   # @brief Parses a string of xml.
   # @param st [in] string from which to pull XML.
   def parseString(self, st):
      self.log.debug("Setting up parser...")
      evt_stream = pulldom.parseString(st)
      self.log.debug("{}Parsing started with Parsable set {}".format('Sub-' if self.active else '', dict((p,self.__parsables[p].tag()) for p in self.__parsables)))
      for x in self._parse_evt_stream(evt_stream):
         yield x
   
   ##
   # @name getSubXml
   # @brief Obtains the child-xml for a given node of a given DOMEventStream.
   # @param evt_stream [in,out] The DOMEventStream to use.
   # @param node [in,out] The node from evt_stream to use.
   # @return string The XML of all child nodes of node.
   # @details Calls evt_stream.expandNode, which removes XML from the DOMEventStream.
   #          Furthermore, inserts the child XML between <_></_> tags.
   #
   def getSubXml(self, evt_stream, node):
      evt_stream.expandNode(node)
      subxml = node.toxml()
      subxml = subxml[subxml.find('>') + 1 : subxml.rfind('</')].strip()
      self.log.debug("Yielded subxml for {}: '''{}'''".format(node.tagName, subxml))
      return '<_>{}</_>'.format(subxml)
   
   ##
   # @name _parse_evt_stream
   # @brief Parses the DOMEventStream.
   # @param evt_stream [in] The DOMEventStream to process.
   def _parse_evt_stream(self, evt_stream):
      dom = Parser.Stack()
      for evt,node in evt_stream:
         if   evt == pulldom.START_ELEMENT and node.tagName != '_':
            self.log.info("Start element: {}".format(node.tagName))
            try:
               dom.push(self.__parsables[node.tagName]())
               if dom.peek().Start(dict((k,node.getAttribute(k)) for k in node.attributes.keys()), evt_stream, node, self):
                  #replicates end element code below. handles parsables that do subparsing
                  self.log.info("End element: {}".format(node.tagName))
                  element = dom.pop()
                  element.End()
                  try:
                     dom.peek().Child(element)
                  except IndexError:
                     yield element
            except KeyError as ke:
               self.log.warning("Invalid element: {}".format(ke.args[0]))
               raise ParseError("Invalid element: {}".format(ke.args[0]))
         elif evt == pulldom.END_ELEMENT and node.tagName != '_':
            self.log.info("End element: {}".format(node.tagName))
            element = dom.pop()
            element.End()
            try:
               dom.peek().Child(element)
            except IndexError:
               yield element
         elif evt == pulldom.CHARACTERS:
            try:
               dom.peek().Cdata(node.nodeValue)
            except IndexError:
               pass #cdata outside any node
         elif evt == pulldom.START_DOCUMENT:
            self.log.info("Parsing started.")
         elif evt == pulldom.END_DOCUMENT:
            self.log.info("Parsing completed.")
         else:
            if node.tagName == '_':
               self.log.debug("Event type '{}' for pseudo-node".format(evt))
            else:
               self.log.debug("Unhandled event type '{}' for node '{}'".format(evt, node))
   