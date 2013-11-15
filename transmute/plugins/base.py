import logging
from   ..Parsing.Parsable      import Parsable
from   ..Parsing.Parser        import Parser, ParseError, ValidationError
from   ..Dispatch.Dispatchable import Dispatchable

__all__  = ["register", "getParsables"]

_logger  = logging.getLogger('transmute.base')

_prefix = ''

class Constants:
   chunksize = {"8" : 8, "16" : 16, "32" : 32}
   bit0      = {"MSb" : object(), "LSb" : object()}

class Detail(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log     = logging.getLogger('transmute.base.Detail')
      self._detail = None
   
   def tag():
      return ':'.join([_prefix, 'detail']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      pass #detail has no complex start tasks
   
   def End(self):
      if self.detail is None:
         raise ParseError('<{}> missing data'.format(self.getTag()))
   
   def Cdata(self, data):
      self.detail = data
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.detail is None:
         raise ValidationError('<{}> missing data'.format(self.getTag()))
   
   @property
   def detail(self):
      return self._detail
   
   @detail.setter
   def detail(self, data):
      self._detail = data

class Brief(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log    = logging.getLogger('transmute.base.Brief')
      self._brief = None
   
   def tag():
      return ':'.join([_prefix, 'brief']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      pass
   
   def End(self):
      if self.brief is None:
         raise ParseError('<{}> missing data'.format(self.getTag()))
   
   def Cdata(self, data):
      self.brief = data
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.brief is None:
         raise ValidationError('<{}> missing data'.format(self.getTag()))
   
   @property
   def brief(self):
      return self._brief
   
   @brief.setter
   def brief(self, data):
      self._brief = data

class Description(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log           = logging.getLogger('transmute.base.Description')
      self._name         = None
      self._brief        = None
      self._abbreviation = None
      self._detail       = None
   
   def tag():
      return ':'.join([_prefix, 'description']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      try:
         self.name         = attrs['name']
         self.abbreviation = attrs['abbreviation']
      except KeyError as ke:
         raise ParseError("<{}> missing {}".format(self.getTag(), ke))
      
      return False
   
   def End(self):
      pass #description does not have complex end tasks
   
   def Cdata(self, data):
      pass #description does not have cdata
   
   def Child(self, child):
      super().Child(child)
      if   child.getTag() == Brief.tag():
         self.brief = child
      elif child.getTag() == Detail.tag():
         self.detail = child
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.brief is None:
         raise ValidationError("<{}> missing <{}>".format(self.getTag(), Brief.tag()))
      if self.detail is None:
         self.detail = self.brief
   
   @property
   def name(self):
      return self._name
   @name.setter
   def name(self, value):
      self._name = value
   
   @property
   def brief(self):
      return self._brief
   @brief.setter
   def brief(self, value):
      self._brief = value
      if self._detail is None:
         self._detail = value
   
   @property
   def abbreviation(self):
      return self._abbreviation
   @abbreviation.setter
   def abbreviation(self, value):
      self._abbreviation = value
   
   @property
   def detail(self):
      return self._detail
   @detail.setter
   def detail(self, value):
      self._detail = value

class Value(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log   = logging.getLogger('transmute.base.Value')
      self._name = None
      self._ival = None
      
   def tag():
      return ':'.join([_prefix, 'value']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      try:
         self.name = attrs['name']
         self.ival = attrs['int']
      except KeyError as ke:
         raise ParseError("<{}> missing {}".format(self.getTag(), ke))
   
   def End(self):
      pass #value has no complex end tasks
   
   def Cdata(self, data):
      pass #value has no cdata
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.name is None:
         raise ValidationError("<{}> missing name attribute".format(self.getTag()))
      if self._ival is None:
         raise ValidationError("<{}> missing int attribute".format(self.getTag()))
   
   @property
   def name(self):
      return self._name
   
   @name.setter
   def name(self, data):
      self._name = data
   
   @property
   def ival(self):
      return self._ival
   
   @ival.setter
   def ival(self, data):
      try:
         int(data)
      except ValueError:
         raise ParseError("<{}> invalid int attribute".format(self.getTag()))
      else:
         self._ival = data

class Values(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log     = logging.getLogger('transmute.base.Values')
      self._name   = None
      self._values = dict()
      
   def tag():
      return ':'.join([_prefix, 'values']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      try:
         self._name = attrs['name']
      except KeyError:
         pass #we allow anonymous values when they have <value> children
   
   def End(self):
      if self.name is None and len(self._values) == 0:
         raise ParseError("<{}> with no name and no <{}> children".format(self.getTag(), Value.tag()))
   
   def Cdata(self, data):
      pass #values has no cdata
   
   def Child(self, child):
      super().Child(child)
      if child.getTag() == Value.tag():
         self._values[child.name] = child
   
   def Validate(self, parent):
      super().Validate(parent)
      if   self.name and len(self._values) == 0:
         valid = False
         current = parent.parent if parent is not None else None
         #skip over the immediate parent (which obviously contains this node)
         while current is not None and not valid:
            try:
               if self.name in parent.values:
                  valid = True
            except AttributeError:
               pass #current does not hold values types, move up
            current = current.parent
         if not valid:
            raise ValidationError("No definition of <{} name=\"{}\">'".format(self.getTag(), self.name))
   
   @property
   def name(self):
      return self._name
   
   @name.setter
   def name(self, data):
      self._name = data
   
   @property
   def values(self):
      return dict((k,self._values[k]) for k in self._values)
   
class Message(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log          = logging.getLogger('transmute.base.Message')
      self._values      = dict()
      self.description  = None
      self._fields      = dict()
      
   def tag():
      return ':'.join([_prefix, 'message']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      pass #@todo
   
   def End(self):
      pass #message has no complex end tasks
   
   def Cdata(self, data):
      pass #message has no cdata
   
   def Child(self, child):
      super().Child(child) #@todo
   
   def Validate(self, parent):
      super().Validate(parent) #@todo
      #check that no field abbreviation is repeated
   
   @property
   def values(self):
      return dict((k,self._values[k]) for k in self._values)

class Protocol(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log = logging.getLogger('transmute.base.Protocol')
      self.messages    = []
      self._values     = dict()
      self.description = None
   
   def tag():
      return ':'.join([_prefix, 'protocol']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      try:
         specified_cs = attrs['chunksize']
         try:
            self.chunksize = Constants.chunksize[specified_cs]
         except KeyError as ke:
            raise ParseError("Invalid chunksize: {}".format(ke))
      except KeyError as ke:
         self.log.info("no chunksize given, using default")
         self.chunksize = Constants.chunksize['8']
      try:
         specified_b0 = attrs['bit0']
         try:
            self.bit0 = Constants.bit0[specified_b0]
         except KeyError as ke:
            raise ParseError("Invalid bit0: {}".format(ke))
      except KeyError as ke:
         self.log.info("no bit0 given, using default")
         self.bit0 = Constants.bit0['LSb']
      self.messages = []
            
      for element in parser.parseString(parser.getSubXml(evt_stream, node)):
         self.Child(element)
      
      return True
   
   def End(self):
      pass #protocol has no complex end tasks
   
   def Cdata(self, data):
      pass #protocol has no cdata
   
   def Child(self, child):
      super().Child(child)
      if   child.getTag() == Message.tag():
         self.messages.append(child)
      elif child.getTag() == Values.tag():
         self._values[child.name] = child
      elif child.getTag() == Description.tag():
         self.description = child
      else:
         self.children.append(child)
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.description is not None:
         self.description.Validate(self)
      else:
         raise ValidationError("{} missing <{}>.".format(self.getTag(), Description.tag()))
      self.log.info("Validation complete for {} '{}'".format(self.getTag(), self.name))
   
   @property
   def name(self):
      try:
         return self.description.name
      except AttributeError:
         return ''
   
   @property
   def values(self):
      return dict((k,self._values[k]) for k in self._values)

def register(args_parser, xml_parser):
   for parsable in [Protocol,
                    Description,
                       Brief,
                       Detail,
                    Values,
                       Value,
                    Message#,
                       #Field,
                          #Position,
                             #Bits,
                          #Weight
                   ]:
      xml_parser.registerParsable(parsable)

def dispatch(dispatchable_obj):
   pass
