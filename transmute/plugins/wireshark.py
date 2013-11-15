import logging
from   sys                import argv
from   ..Parsing.Parsable import Parsable
from   ..Parsing.Parser   import ParseError
from   .base              import Protocol

__all__  = ["register", "getParsables"]

_logger  = logging.getLogger('transmute.wireshark')

_prefix = 'ws'

args_ns = None

class RegisterParsable(Parsable):
   def __init__(self):
      super().__init__()
      self.table = ''
      self.value = ''
   
   def tag():
      return ':'.join([_prefix, 'register']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      if args_ns.ws:
         try:
            self.table = attrs['table']
            self.value = attrs['value']
         except KeyError as ki:
            raise ParseError("{} missing required attribute '{}'".format(self.getTag(), ki))
   
   def End(self):
      pass #ws:register does not have complex ending tasks
   
   def Cdata(self, data):
      pass #ws:register does not have cdata
   
   def Child(self, child):
      pass #ws:register does not have child nodes
   
   def Validate(self, parent):
      super().Validate(parent)

def register(args_parser, xml_parser):
   global args_ns
   args_group = args_parser.add_argument_group(title='wireshark', description='The wireshark description.@todo')
   args_group.add_argument('-ws', '--wireshark', action='store_true', default=False)
   args_ns,argv = args_parser.parse_known_args()

def dispatch(dispatchable_obj):
   if args_ns.wireshark and dispatchable_obj.getTag() == Protocol.tag():
      _logger.debug('Beginning dispatch for {} protocol'.format(dispatchable_obj.name))
      #@todo write out the wireshark files for this protocol