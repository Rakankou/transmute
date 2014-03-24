import logging
import itertools
import operator
from   abc                     import ABCMeta, abstractmethod
from   collections             import OrderedDict
from   ..Parsing.Parsable      import Parsable
from   ..Parsing.Parser        import Parser, ParseError, ValidationError
from   ..Dispatch.Dispatchable import Dispatchable

__all__  = ["register", "dispatch", "Protocol",  "Description",
            "Brief",    "Detail",   "Values",    "Value",
            "Message",  "Field",    "Position",  "Bits",
            "Chunks",   "Weight",                "Constants",
            "Header",   "Trailer",  "Version"
           ]

_logger  = logging.getLogger('transmute.base')

_prefix = ''

class Constants:
   chunksize = {"8" : 8, "16" : 16, "32" : 32}
   bit0      = {"MSb" : object(), "LSb" : object()}
   endian    = {"big" : object(), "little" : object()}

class Detail(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log     = logging.getLogger('transmute.base.Detail')
      self._detail = None
   
   def tag():
      return ':'.join([_prefix, 'detail']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
      
      return False
   
   def End(self):
      if self.detail is None:
         raise ParseError('<{}> missing data'.format(self.getTag()))
   
   def Cdata(self, data):
      self.detail = data
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      if self.detail is None:
         raise ValidationError('<{}> missing data'.format(self.getTag()))
      super().Validate(parent)
   
   @property
   def detail(self):
      return self._detail
   
   @detail.setter
   def detail(self, data):
      self._detail = data
   
   def __str__(self):
      return self._detail

class Brief(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log    = logging.getLogger('transmute.base.Brief')
      self._brief = None
   
   def tag():
      return ':'.join([_prefix, 'brief']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
      
      return False
   
   def End(self):
      if self.brief is None:
         raise ParseError('<{}> missing data'.format(self.getTag()))
   
   def Cdata(self, data):
      self.brief = data
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      if self.brief is None:
         raise ValidationError('<{}> missing data'.format(self.getTag()))
      super().Validate(parent)
   
   @property
   def brief(self):
      return self._brief
   
   @brief.setter
   def brief(self, data):
      self._brief = data
   
   def __str__(self):
      return self._brief

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
      super().Start(attrs, evt_stream, node, parser)
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
      if self.brief is None:
         raise ValidationError("<{}> missing <{}>".format(self.getTag(), Brief.tag()))
      if self.detail is None:
         self.detail = self.brief
      super().Validate(parent)
   
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
      super().Start(attrs, evt_stream, node, parser)
      try:
         self.name = attrs['name']
         self.ival = attrs['int']
      except KeyError as ke:
         raise ParseError("<{}> missing {}".format(self.getTag(), ke))
      
      return False
   
   def End(self):
      pass #value has no complex end tasks
   
   def Cdata(self, data):
      pass #value has no cdata
   
   def Child(self, child):
      super().Child(child)
   
   def Validate(self, parent):
      if self.name is None:
         raise ValidationError("<{}> missing name attribute".format(self.getTag()))
      if self._ival is None:
         raise ValidationError("<{}> missing int attribute".format(self.getTag()))
      super().Validate(parent)
   
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
      self._values = OrderedDict()
      
   def tag():
      return ':'.join([_prefix, 'values']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      self._name   = None
      self._values = OrderedDict()
      super().Start(attrs, evt_stream, node, parser)
      try:
         self._name = attrs['name']
      except KeyError:
         pass #we allow anonymous values when they have <value> children
      
      return False
   
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
      if   self.name and len(self._values) == 0:
         valid = False
         current = parent.parent if parent is not None else None
         #skip over the immediate parent (which obviously contains this node)
         while current is not None and not valid:
            try:
               self.log.debug("Searching ancestor <{}> values namespace: [{}]".format(current.getTag(), ', '.join(map(str, (v for v in current.values)))))
               #find teh defining node: i.e. the first node with defined values inside
               if self.name in current.values and len(current.values[self.name]) > 0:
                  valid = True
            except AttributeError:
               pass #current does not hold values types, move up
            current = current.parent
         if not valid:
            raise ValidationError("No definition of <{} name=\"{}\">'".format(self.getTag(), self.name))
      super().Validate(parent)
   
   @property
   def name(self):
      return self._name
   
   @name.setter
   def name(self, data):
      self._name = data
   
   @property
   def values(self):
      return OrderedDict((k,self._values[k]) for k in self._values)
   
   def __len__(self):
      return len(self._values)
   
   def __iter__(self):
      for v in self._values:
         yield v
   
class Bits(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log   = logging.getLogger('transmute.base.Bits')
      self.start = 0
      self._end  = None
      self._mask = None
   
   def tag():
      return ':'.join([_prefix, 'bits']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      self.start = 0
      self._end  = None
      self._mask = None
      super().Start(attrs, evt_stream, node, parser)
      try:
         self.start = int(attrs['start'])
      except KeyError:
         raise ParseError("Missing start attribute for <{}>".format(self.getTag()))
      except ValueError as ve:
         raise ParseError("Invalid start attribute for <{}> '{}'".format(self.getTag(), ve))
      
      if 'end' in attrs.keys() and 'mask' in attrs.keys():
         raise ParseError("<{}> with both end and mask attributes".format(self.getTag()))
      elif 'end' in attrs.keys():
         try:
            self._end = int(attrs['end'])
         except ValueError as ve:
            raise ParseError("Invalid end attribute for <{}> '{}'".format(self.getTag(), ve))
      elif 'mask' in attrs.keys():
         try:
            self._end = int(attrs['mask'])
         except ValueError as ve:
            raise ParseError("Invalid mask attribute for <{}> '{}'".format(self.getTag(), ve))
      else:
         raise ParseError("<{}> without end or mask attributes".format(self.getTag()))
      
      return False
   
   def Child(self, child):
      super().Child(child)
   
   def Cdata(self, data):
      super().Cdata(data)
   
   def End(self):
      super().End()
   
   def Validate(self, parent):
      if self._end is not None:
         if self._end >= parent.chunksize:
            raise ValidationError("end attribute too large ({}) for chunksize ({})".format(self._end, parent.chunksize))
         if self._end < self.start:
            raise ValidationError("<{}> has reversed start and end attributes.".format(self.getTag()))
      if self._mask is None:
         self._mask = self.buildMask(parent.chunksize, parent.bit0)
      super().Validate(parent)
   
   def buildMask(self, chunksize, bit0):
      if self._end is None:
         return self._mask
      else:
         mask = 0
         mlen = self._end - self.start + 1
         if mlen >= 1:
            mask = int('1' * mlen, 2)
            shift = operator.lshift if bit0 == Constants.bit0 else operator.rshift
            if bit0 == Constants.bit0['MSb']:
               #justify the mask for MSb i.e. 00000111 -> 11100000
               #this because the shift assumption below is that the 1 string starts at bit0
               mask = mask << (chunksize - mlen)
            mask = shift(mask, chunksize - self.start)
         return mask
   
   def __len__(self):
      if   self._end is not None:
         return self._end - self.start + 1
      elif self._mask is not None:
         return len(bin(self._mask)[2:].strip('0'))
      else:
         return 0

class Chunks(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log   = logging.getLogger('transmute.base.Chunks')
      self.length = None
   
   def tag():
      return ':'.join([_prefix, 'chunks']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      self.length = None
      super().Start(attrs, evt_stream, node, parser)
      try:
         self.length = int(attrs['length'])
      except KeyError:
         raise ParseError("Missing length attribute for <{}>".format(self.getTag()))
      except ValueError as ve:
         raise ParseError("Invalid length attribute for <{}> '{}'".format(self.getTag(), ve))
      
      return False
   
   def Child(self, child):
      super().Child(child)
   
   def Cdata(self, data):
      super().Cdata(data)
   
   def End(self):
      super().End()
   
   def Validate(self, parent):
      super().Validate(parent)
   
   def __len__(self):
      return self.length
   
   def __int__(self):
      return self.length if self.length is not None else 0

class Position(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log        = logging.getLogger('transmute.base.Position')
      self.index      = 0
      self._bits      = None
      self._chunks    = None
      self._chunksize = None
   
   def tag():
      return ':'.join([_prefix, 'position']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      self.index      = 0
      self._bits      = None
      self._chunks    = None
      self._chunksize = None
      super().Start(attrs, evt_stream, node, parser)
      try:
         self.index = int(attrs['index'])
      except KeyError:
         raise ParseError("Missing index attribute for <{}>".format(self.getTag()))
      except ValueError as ve:
         raise ParseError("Invalid index attribute for <{}> '{}'".format(self.getTag(), ve))
      
      return False
   
   def Child(self, child):
      super().Child(child)
      if   child.getTag() == Bits.tag():
         if self._bits is None:
            if self._chunks is None:
               self._bits = child
            else:
               raise ParseError("<{}> with both <{}> and <{}> children".format(self.getTag(), Bits.tag(), Chunks.tag()))
         else:
            raise ParseError("<{}> with multiple <{}> children".format(self.getTag(), child.getTag()))
      elif child.getTag() == Chunks.tag():
         if self._chunks is None:
            if self._bits is None:
               self._chunks = child
            else:
               raise ParseError("<{}> with both <{}> and <{}> children".format(self.getTag(), Bits.tag(), Chunks.tag()))
         else:
            raise ParseError("<{}> with multiple <{}> children".format(self.getTag(), child.getTag()))
   
   def Cdata(self, data):
      super().Cdata(data)
   
   def End(self):
      super().End()
      if self._bits is None and self._chunks is None:
         raise ParseError("<{}> missing <{}> or <{}> child".format(self.getTag(), Bits.tag(), Chunks.tag()))
   
   def Validate(self, parent):
      super().Validate(parent)
      self._chunksize = self.chunksize
   
   @property
   def chunksize(self):
      if self._chunksize is not None:
         return self._chunksize
      if self.parent is not None:
         return self.parent.chunksize
   
   @property
   def endian(self):
      if self.parent is not None:
         return self.parent.endian
   
   @property
   def bit0(self):
      if self.parent is not None:
         return self.parent.bit0
   
   @property
   def bitlength(self):
      return len(self._chunks) * self.chunksize if self._chunks is not None else len(self._bits)
   
   @property
   def bitstart(self):
      return self._bits.start if self._bits is not None else 0
   
   @property
   def bitmask(self):
      return int(('F' * (self.chunksize / 4)) * len(self._chunks), 16) if self._chunks is not None else self._bits.buildMask(self.chunksize, self.bit0)
   
   @property
   def chunklength(self):
      return self._chunks.length if self._chunks is not None else (self.bitlength // self.chunksize + (1 if self.bitlength % self.chunksize else 0))
   
   def __or__(self, other):
      if not isinstance(other, Position):
         raise NotImplemented("Unusable type '{}' for concatenation with Position type".format(type(other)))
      if self.chunksize != other.chunksize:
         raise NotImplemented("Cannot concatenate Position with different chunk sizes")
      npos = Position()
      nck  = Chunks()
      npos.index = min(self.index, other.index)
      terminus = max(self.index  + (self.bitlength  / self.chunksize),
                     other.index + (other.bitlength / other.chunksize)
                    )
      nck.length = max(1, terminus - npos.index)
      npos.Child(nck)
      return npos
   
   @staticmethod
   def create(index, chunks):
      npos = Position()
      nck  = Chunks()
      npos.index = index
      nck.length = chunks
      npos.Child(nck)
      return npos

class Weight(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log     = logging.getLogger('transmute.base.Weight')
      self._lsb    = None
      self._offset = None
   
   def tag():
      return ':'.join([_prefix, 'weight']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      self._lsb    = None
      self._offset = None
      super().Start(attrs, evt_stream, node, parser)
      try:
         self._lsb = float(attrs['lsb'])
      except KeyError:
         raise ParseError("Missing lsb attribute for <{}>".format(self.getTag()))
      except ValueError as ve:
         raise ParseError("Invalid lsb attribute for <{}> '{}'".format(self.getTag(), ve))
      else:
         if self.lsb == 0.0:
            raise ParseError("Invalid lsb attribute for <{}> '{}'".format(self.getTag(), self.lsb))
      try:
         self._offset = float(attrs['offset'])
      except KeyError:
         self.log.debug("No offset attribute. Using default.")
         self._offset = 0.0
      except ValueError as ve:
         raise ParseError("Invalid offset attribute for <{}> '{}'".format(self.getTag(), ve))
      
      return False
   
   def Child(self, child):
      super().Child(child)
   
   def Cdata(self, data):
      super().Cdata(data)
   
   def End(self):
      super().End()
   
   def Validate(self, parent):
      super().Validate(parent)
   
   @property
   def lsb(self):
      return self._lsb if self._lsb is not None else 0.0
   
   @property
   def offset(self):
      return self._offset if self._offset is not None else 0.0

class Field(Parsable, Dispatchable):
   class FTypeHandler(metaclass = ABCMeta):
      def __init__(self, typename, fld):
         self.log       = logging.getLogger('transmute.base.Field.FTypeHandler')
         self._field    = fld
         self._typename = typename
         self._attrs    = dict()
      @abstractmethod
      def Start(self, attrs):
         self._attrs    = attrs
      @abstractmethod
      def Child(self, child):
         pass
      @abstractmethod
      def Validate(self, parent):
         pass
      @property
      def typename(self):
         return self._typename
      @property
      def attrs(self):
         return {k:self._attrs[k] for k in self._attrs.keys()}
   class GenericFTypeHandler(FTypeHandler):
      def __init__(self, typename, fld):
         super().__init__(typename, fld)
      def Start(self, attrs):
         super().Start(attrs)
      def Child(self, child):
         super().Child(child)
      def Validate(self, parent):
         super().Validate(parent)
   class SignableGenericFTypeHandler(GenericFTypeHandler):
      def __init__(self, typename, fld):
         super().__init__(typename, fld)
         self._field.unsigned = False
      def Start(self, attrs):
         super().Start(attrs)
         self._field.unsigned = 'unsigned' in self.typename
   class EnumerationFTypeHandler(GenericFTypeHandler):
      def __init__(self, typename, fld):
         super().__init__(typename, fld)
      def Child(self, child):
         super().Child(child)
         if child.getTag() == Values.tag():
            if self._field._values is not None:
               raise ParseError("Multiple <{}> at the same scope under <{}>".format(child.getTag(), self.getTag()))
            else:
               self._field._values = child
      def Validate(self, parent):
         super().Validate(parent)
         if self._field._values.name is not None and len(self._field._values) == 0:
            self._field._values.Validate(parent)
   class WeightedFTypeHandler(SignableGenericFTypeHandler):
      def __init__(self, typename, fld):
         super().__init__(typename, fld)
      def Child(self, child):
         super().Child(child)
         if child.getTag() == Weight.tag():
            self._field._weight = child
      def Validate(self, parent):
         super().Validate(parent)
         self._field._weight.Validate(parent)
   
   FTypes = {'undecoded'         : GenericFTypeHandler,
             'bool'              : GenericFTypeHandler,
             'boolean'           : GenericFTypeHandler,
             'enum'              : EnumerationFTypeHandler,
             'enumeration'       : EnumerationFTypeHandler,
             'weighted'          : WeightedFTypeHandler,
             'unsigned weighted' : WeightedFTypeHandler,
             'float'             : GenericFTypeHandler,
             'double'            : GenericFTypeHandler,
             'int'               : SignableGenericFTypeHandler,
             'integer'           : SignableGenericFTypeHandler,
             'unsigned int'      : SignableGenericFTypeHandler,
             'unsigned integer'  : SignableGenericFTypeHandler
            }
   
   def __init__(self):
      super().__init__()
      self.log           = logging.getLogger('transmute.base.Field')
      self.description   = None
      self.position      = None
      self._endian       = None
      self._values       = None
      self.ftype_handler = Field.FTypes['undecoded']('', {})
      self.ftype         = 'undecoded'
      
   def tag():
      return ':'.join([_prefix, 'field']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
      self.description   = None
      self.position      = None
      self._endian       = None
      self._values       = None
      self.ftype_handler = Field.FTypes['undecoded']('', {})
      self.ftype         = 'undecoded'
      try:
         self.ftype_handler = Field.FTypes[attrs['type']](attrs['type'], self)
         self.ftype = attrs['type']
      except KeyError as ke:
         raise ParseError("Unknown field type '{}'".format(attrs['type']))
      else:
         self.ftype_handler.Start(attrs)
      
      if 'endian' in attrs.keys():
         try:
            self._endian = Constants.endian[attrs['endian']]
         except KeyError as ke:
            self._endian = None
            raise ParseError("Invalid endian attribute '{}' in <{}>".format(ke, self.getTag()))
            
      for element in parser.parseString(parser.getSubXml(evt_stream, node)):
         self.Child(element)
      
      return True
   
   def End(self):
      pass #message has no complex end tasks
   
   def Cdata(self, data):
      pass #message has no cdata
   
   def Child(self, child):
      super().Child(child)
      self.ftype_handler.Child(child)
      if   child.getTag() == Description.tag():
         self.description = child
      elif child.getTag() == Position.tag():
         self.position = child
      
   def Validate(self, parent):
      if self._endian is None:
         if parent is not None:
            self._endian = parent.endian
         else:
            raise ValidationError("<{}> missing endian value".format(self.getTag()))
      if self.description is not None:
         self.description.Validate(self)
      else:
         raise ValidationError("{} missing <{}>.".format(self.getTag(), Description.tag()))
      super().Validate(parent)
      self.ftype_handler.Validate(parent)
   
   @property
   def name(self):
      try:
         return self.description.name
      except AttributeError:
         return ''
   
   @property
   def abbreviation(self):
      try:
         return self.description.abbreviation
      except AttributeError:
         return ''
   
   @property
   def chunksize(self):
      if self.parent is not None:
         return self.parent.chunksize
   
   @property
   def endian(self):
      if self._endian is not None:
         return self._endian
      if self.parent is not None:
         return self.parent.endian
   
   @property
   def bit0(self):
      if self.parent is not None:
         return self.parent.bit0
   
   @property
   def values(self):
      if self._values is not None:
         return self._values

class Message(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log          = logging.getLogger('transmute.base.Message')
      self._values      = dict()
      self.description  = None
      self._fields      = dict()
      self._groups      = dict()
      self._endian      = None
      self.header       = None
      self.trailer      = None
      
   def tag():
      return ':'.join([_prefix, 'message']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
      self._values      = dict()
      self.description  = None
      self._fields      = dict()
      self._groups      = dict()
      self._endian      = None
      self.header       = None
      self.trailer      = None
            
      for element in parser.parseString(parser.getSubXml(evt_stream, node)):
         self.Child(element)
      
      return True
   
   def End(self):
      pass #message has no complex end tasks
   
   def Cdata(self, data):
      pass #message has no cdata
   
   def Child(self, child):
      super().Child(child)
      if   child.getTag() == Values.tag():
         if child.name not in self._values.keys():
            self._values[child.name] = child
         else:
            raise ParseError("Duplicate <{}> at the same scope under <{}>".format(child.getTag(), self.getTag()))
      elif child.getTag() == Field.tag():
         if child.abbreviation not in self._fields.keys():
            self._fields[child.abbreviation] = child
         else:
            raise ParseError("<{}> with duplicate fields {}".format(self.getTag(), child.abbreviation))
      elif child.getTag() == Description.tag():
         self.description = child
      elif child.getTag() == Header.tag():
         self.header = child
      elif child.getTag() == Trailer.tag():
         self.trailer = child
      
   def Validate(self, parent):
      if self._endian is None:
         if parent is not None:
            self._endian = parent.endian
         else:
            raise ValidationError("<{}> missing endian value".format(self.getTag()))
      super().Validate(parent)
      if self.description is not None:
         self.description.Validate(self)
      else:
         raise ValidationError("{} missing <{}>.".format(self.getTag(), Description.tag()))
      if any(map(lambda combo: self._fields[combo[0]].abbreviation == self._fields[combo[r]].abbreviation, itertools.combinations(self._fields.keys(), 2))):
         raise ValidationError("<{}> '{}' has repeated {} abbreviations".format(self.getTag(), self.description.name, Field.tag()))
      if any(map(lambda combo: self._groups[combo[0]].abbreviation == self._groups[combo[r]].abbreviation, itertools.combinations(self._groups.keys(), 2))):
         raise ValidationError("<{}> '{}' has repeated {} abbreviations".format(self.getTag(), self.description.name, Group.tag()))
      if any(map(lambda k: k in self._groups.keys(), self._fields.keys())):
         raise ValidationError("<{}> '{}' has conflicting {} and {} abbreviations".format(self.getTag(), self.description.name, Group.tag(), Field.tag()))
      #@todo there is more field validation that can be done here
      #      e.g. ensure all bits are defined, ensure fields don't overlap, etc.
   
   @property
   def name(self):
      try:
         return self.description.name
      except AttributeError:
         return ''
   
   @property
   def abbreviation(self):
      try:
         return self.description.abbreviation
      except AttributeError:
         return ''
   
   @property
   def values(self):
      return dict((k,self._values[k]) for k in self._values.keys())
   
   @property
   def fields(self):
      return dict((k,self._fields[k]) for k in self._fields.keys())
   
   @property
   def chunksize(self):
      if self.parent is not None:
         return self.parent.chunksize
   
   @property
   def endian(self):
      if self._endian is not None:
         return self._endian
      if self.parent is not None:
         return self.parent.endian
   
   @property
   def bit0(self):
      if self.parent is not None:
         return self.parent.bit0
   
   @property
   def position(self):
      keygen = (k for k in self._fields.values())
      pos = next(keygen).position
      for f in keygen:
         pos = pos | f.position
      if self.header is not None:
         pos = pos | self.header.position
      if self.trailer is not None:
         pos = pos | self.trailer.position
      return pos
   
   def hasFields(self):
      rv = False
      if self.header is not None:
         rv = self.header.hasFields()
      if not rv and self.trailer is not None:
         rv = self.trailer.hasFields()
      if not rv and len(self._fields) > 0:
         rv = True
      return rv

class Header(Message):
   def __init__(self):
      super().__init__()
      self.log          = logging.getLogger('transmute.base.Header')
      
   def tag():
      return ':'.join([_prefix, 'header']).lstrip(':')

class Trailer(Message):
   def __init__(self):
      super().__init__()
      self.log          = logging.getLogger('transmute.base.Trailer')
      
   def tag():
      return ':'.join([_prefix, 'trailer']).lstrip(':')

class Version(Parsable, Dispatchable):
   __components = ['major','minor','micro','extra']
   
   def __init__(self):
      super().__init__()
      self.log = logging.getLogger('transmute.base.Version')
      self._v = dict()
   
   def tag():
      return ':'.join([_prefix, 'version']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
      self._v = dict()
      for slice in Version.__components:
         try:
            self._v[slice] = attrs[slice]
         except KeyError as ke:
            self.log.info('{tag} missing {slice} component, using empty'.format(tag = self.getTag(), slice = slice))
            self._v[slice] = ''
   
   def End(self):
      pass #version has no complex end tasks
   
   def Cdata(self, data):
      pass #version has no cdata
   
   def Child(self, child):
      super().Child(child)
      pass #version has no child nodes
   
   def Validate(self, parent):
      super().Validate(parent)
      if len(self._v) == 0:
         raise ValidationError("<{}> with no data".format(self.getTag()))
   
   @property
   def data(self):
      return dict((k, self._v[k]) for k in Version.__components)
   
   @staticmethod
   def create(components):
      v = Version()
      for slice in Version.__components:
         try:
            v._v[slice] = components[slice]
         except KeyError as ke:
            v._v[slice] = ''
      return v

class Protocol(Parsable, Dispatchable):
   def __init__(self):
      super().__init__()
      self.log = logging.getLogger('transmute.base.Protocol')
      self.messages    = dict()
      self._values     = dict()
      self.description = None
      self._endian     = None
      self.chunksize   = None
      self.bit0        = None
      self.header      = None
      self.trailer     = None
      self._version    = None
   
   def tag():
      return ':'.join([_prefix, 'protocol']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      super().Start(attrs, evt_stream, node, parser)
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
      try:
         specified_endian = attrs['endian']
         try:
            self._endian = Constants.endian[specified_endian]
         except KeyError as ke:
            raise ParseError("Invalid endian value: {}".format(ke))
      except KeyError as ke:
         self.log.info("no endian given, using default")
         self._endian = Constants.endian['big']
      self.messages    = dict()
      self._values     = dict()
      self.description = None
      self.header      = None
      self.trailer     = None
      self._version    = None
            
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
         if child.abbreviation not in self.messages.keys():
            self.messages[child.abbreviation] = child
         else:
            raise ParseError("<{}> {} has <{}> with duplicate abbreviation {}".format(self.getTag(), self.name, Message.tag(), child.abbreviation))
      elif child.getTag() == Values.tag():
         if child.name not in self._values.keys():
            self._values[child.name] = child
         else:
            raise ParseError("Duplicate <{}> at the same scope under <{}>".format(child.getTag(), self.getTag()))
      elif child.getTag() == Description.tag():
         self.description = child
      elif child.getTag() == Header.tag():
         self.header = child
      elif child.getTag() == Trailer.tag():
         self.trailer = child
      elif child.getTag() == Version.tag():
         if self._version is None:
            self._version = child
         else:
            raise ParseError("<{}> {} has multiple <{}>".format(self.getTag(), self.name, Version.tag()))
   
   def Validate(self, parent):
      super().Validate(parent)
      if self.description is not None:
         self.description.Validate(self)
      else:
         raise ValidationError("{} missing <{}>.".format(self.getTag(), Description.tag()))
      if self._version is None:
         self._version = Version.Create({'major':1, 'minor':0})
         self.log.info("<{}> has no version, using default".format(self.getTag()))
      if any(map(lambda combo: self.messages[combo[0]].abbreviation == self.messages[combo[r]].abbreviation, itertools.combinations(self.messages.keys(), 2))):
         raise ValidationError("<{}> '{}' has repeated {} abbreviations".format(self.getTag(), self.description.name, Message.tag()))
      self.log.info("Validation complete for {} '{}'".format(self.getTag(), self.name))
   
   @property
   def name(self):
      try:
         return self.description.name
      except AttributeError:
         return ''
   
   @property
   def abbreviation(self):
      try:
         return self.description.abbreviation
      except AttributeError:
         return ''
   
   @property
   def values(self):
      return dict((k,self._values[k]) for k in self._values)
   
   @property
   def endian(self):
      return self._endian
   
   def getField(self, abbreviation):
      self.log.debug("Searching for {} in {}".format(abbreviation, self.abbreviation))
      def search(chunks):
         self.log.debug("   Searching {} for {}".format(chunks, abbreviation))
         for c in chunks.values():
            self.log.debug("      Searching {} for {}".format(c, abbreviation))
            for field in c.fields.values():
               self.log.debug("         Comparing {} to {}".format(field, abbreviation))
               if field.abbreviation == abbreviation:
                  self.log.debug("         Selecting {}".format(field))
                  return field
                  self.log.debug("         Rejecting {}".format(field))
      f = search(self.messages)
      if f is None and self.header is not None:
         f = search(dict(((self.header.abbreviation, self.header),)))
      if f is None and self.trailer is not None:
         f = search(dict(((self.trailer.abbreviation, self.trailer),)))
      return f
   
   def hasField(self, abbreviation):
      return self.getField(abbreviation) is not None
   
   @property
   def position(self):
      return Position.create(0, -1)
   
   def hasFields(self):
      rv = False
      if self.header is not None:
         rv = self.header.hasFields()
      if not rv and self.trailer is not None:
         rv = self.trailer.hasFields()
      return rv
   
   @property
   def version(self):
      return self._version
            

def register(args_parser, xml_parser):
   for parsable in [Protocol,
                    Version,
                    Description,
                       Brief,
                       Detail,
                    Values,
                       Value,
                    Message, Header, Trailer,
                       Field,
                          Position,
                             Bits,
                             Chunks,
                          Weight
                   ]:
      xml_parser.registerParsable(parsable)

def dispatch(dispatchable_obj):
   pass

def setFType(xml_names, ftype_handler):
   if type(ftype_handler) == Field.FTypeHandler:
      for name in xml_names:
         Field.FTypes[name] = ftype_handler
