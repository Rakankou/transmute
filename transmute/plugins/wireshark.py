import logging
import os
from   argparse                import ArgumentTypeError
from   sys                     import argv
from   ..                      import version_string as transmute_version
from   ..Parsing.Parsable      import Parsable
from   ..Parsing.Parser        import ParseError
from   .base                   import Protocol
from   ..Dispatch.Dispatchable import DispatchError

##
# @brief The application version number.
version = (0, 0, '1a')

version_string = '.'.join(str(v) for v in version)

__all__  = ["register", "Register"]

_logger  = logging.g etLogger('transmute.wireshark')

_prefix = 'ws'

args_ns = None

def force_folder(path):
   if os.path.isdir(path):
      return path
   elif os.path.exists(path):
      raise ValueError("'{}' already exists and is not a directory.".format(path))
   else:
      try:
         os.mkdir(path)
      except OSError as ose:
         raise ValueError("Cannot create directory '{}'".format(path))

def folder_type(path):
   try:
      force_folder(path)
   except ValueError as ve:
      raise ArgumentTypeError(ve)

class Register(Parsable):
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
      super().Validate(self)

def register(args_parser, xml_parser):
   global args_ns
   args_group = args_parser.add_argument_group(title='wireshark', description='These arguments control the wireshark output.')
   args_group.add_argument('-ws', '--wireshark',      action='store_true', default=False,                 help="Enable wireshark output.")
   args_group.add_argument('-wso', '--wireshark-out', default='.',         type=folder_type, dest='path', help="Change the wireshark output folder (default is the current working directory).")
   args_ns,argv = args_parser.parse_known_args()
   for parsable in [Register
                   ]:
      xml_parser.registerParsable(parsable)



#
_ws_text = { 'header' : "/* \n * File: {filename}\n * Description: {description}\n * Generated using transmute {transmute_version} Wireshark plugin {plugin_version}\n */\n".format({'filename':'{filename}','description':'{description}','transmute_version':transmute_version,'plugin_version':version_string}),
             #@todo
           }

def dispatch(dispatchable_obj):
   if args_ns.wireshark and dispatchable_obj.getTag() == Protocol.tag():
      _logger.debug('Beginning dispatch for {} protocol'.format(dispatchable_obj.name))
      folder = os.path.join(args_ns.path, dispatchable_obj.abbreviation)
      try:
         force_folder(folder)
      except ValueError as ve:
         raise DispatchError(ve)
      with open(os.path.join(folder, 'packet-{}.c'.format(dispatchable_obj.abbreviation)) as cfile:
         with open(os.path.join(folder, 'packet-{}.h'.format(dispatchable_obj.abbreviation)) as hfile:
            cfile.write(_ws_text['header'].format({'filename':cfile.name, description:"The implementation file for the {} protocol".format(dispatchable_obj.name)}))
            hfile.write(_ws_text['header'].format({'filename':hfile.name, description:"The header file for the {} protocol".format(dispatchable_obj.name)}))
            hfile.write('#ifndef {include_guard}\n#define {include_guard}\n'.format({'include_guard':'{}_'.format(hfile.name.upper().replace('-','_').replace('.','_'))}))
            
            #@todo write out the wireshark files for this protocol
            
            hfile.write('#endif\n')
