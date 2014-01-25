import logging
import os
from   argparse                import ArgumentTypeError
from   sys                     import argv
from   ..                      import version_string as transmute_version
from   ..Parsing.Parsable      import Parsable
from   ..Parsing.Parser        import ParseError
from   .base                   import Protocol, Values
from   ..Dispatch.Dispatchable import DispatchError

##
# @brief The application version number.
version = (0, 0, '1a')

version_string = '.'.join(str(v) for v in version)

__all__  = ["register", "Register", "dispatch"]

_logger  = logging.getLogger('transmute.wireshark')

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
      super().Validate(parent)

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
_ws_text = { 'header_comment'    : "/* \n * File: {{filename}}\n * Description: {{description}}\n * Generated using transmute {transmute_version} Wireshark plugin {plugin_version}\n */\n".format(**{'transmute_version':transmute_version,'plugin_version':version_string}),
             'header_includes'   : "#include \"config.h\"\n#include <glib.h>\n#include <epan/packet.h>\n#include <epan/proto.h>",
             'source_includes'   : "#include \"packet-{name}.h\"\n",
             'enum'              : "typedef enum enum_{name} {{\n{values}\n}} {name};\n",
             'enum_value'        : "{name} = {value}",
             'vs_value'          : "{{{name}, \"{name}\"}}",
             'value_string'      : "const value_string vs_{name}[] = {{\n{values},{{0, NULL}}\n}};\n",
             'true_false_string' : "const true_false_string tfs_{name} = {{{vtrue}, {vfalse}}};\n",
             'dissect_fxn_decl'  : "static void dissect_{name}(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)",
             'dissect_fxn_vars'  : "int offset = 0;\n   proto_tree *{name}_tree;\n   proto_item *pItem;\n",
             'dissect_fxn_cols'  : "col_set_str(pinfo->cinfo, COL_PROTOCOL, \"{name}\");\n   col_clear(pinfo->cinfo, COL_INFO);\n",
             'register_fxn_decl' : "void proto_register_{name}(void)",
             'handoff_fxn_decl'  : "void proto_reg_handoff_{name}(void)",
             'handoff_fxn_vars'  : "dissector_handle_t {name}_handle;\n",
             'indent'            : "   ",
             'header_field'      : '''{indent}{{&hf_{name},\n{indent}{indent}{{"{brief}", "{abbreviation}", FT_{ftype}, BASE_{btype}, {VALS}, {mask},\n{indent}{indent}{indent}"{detail}", HFILL}}}},\n'''
           }

_ws_ftypes = {'undecoded'         : 'NONE',
              'bool'              : 'BOOL',
              'boolean'           : 'BOOL',
              'enum'              : 'UINT',
              'enumeration'       : 'UINT',
              'weighted'          : 'INT',
              'unsigned weighted' : 'UINT',
              'float'             : 'FLOAT',
              'double'            : 'DOUBLE',
              'int'               : 'INT',
              'integer'           : 'INT',
              'unsigned int'      : 'UINT',
              'unsigned integer'  : 'UINT'
             }

def ws_header_field(f):
   attrs = {'indent'      : _ws_text['indent'],
            'name'        : abbr2name(f.description.abbreviation),
            'brief'       : f.description.brief,
            'abbreviation': f.description.abbreviation,
            'ftype'       : '', #@todo
            'btype'       : '', #@todo
            'VALS'        : '', #@todo
            'mask'        : '', #@todo
            'detail'      : f.description.detail
           }
   pass #@todo
   return '{indent}{s}'.format(**{
               'indent':_ws_text['indent'],
               's':_ws_text['header_field'].format(**attrs).replace(
                  '\n','\n{indent}'.format(**{'indent':_ws_text['indent']}))})

def is_tfs(e):
   return (len(e) == 2) and (tuple(e.values[k] for k in e.values()) in [(0,1), (1,0)])

def tfs_get(v, val):
   if not is_tfs(v):
      raise DispatchError("{} is not a true_false_string".format(v.name))
   for k in v.values.keys():
      if v.values[k] == val:
         return k

def var_decl(v):
   return ''.join((v[:v.index('=')].rstrip(),';'))

def abbr2name(abbreviation):
   return abbreviation.replace('.','_').replace('-','_')

def dispatch_node(dispatchable_obj, namespace):
   if hasattr(dispatchable_obj, 'values') and dispatchable_obj.getTag() != Values.tag():
      for vs in dispatchable_obj.values.values():
         if vs.name in (namespace['enums'].keys() | namespace['value_strings'].keys() | namespace['true_false_strings'].keys()):
            raise DispatchError("More than one enumeration with name {name}".format(name = vs.name))
         namespace['enums'][vs.name] = _ws_text['enum'].format(name=vs.name, values=',\n'.join([_ws_text['enum_value'].format(name=v[0],value=v[1]) for v in vs.values]))
         if is_tfs(vs):
            namespace['true_false_strings'][vs.name] = "{indent}{tfs}".format(**{'indent':_ws_text['indent'], 'tfs':_ws_text['true_false_string'].format(name=vs.name, vtrue=tfg_get(vs,1),vfalse=tfs_get(vs,0))})
         else:
            namespace['value_strings'][vs.name] = "{indent}{vs}".format(**{'indent':_ws_text['indent'], 'vs':_ws_text['value_string'].format(name=vs.name, values=',\n'.join([_ws_text['vs_value'].format(name=v) for v in vs.values.keys()]))})
   pass #@todo was there anything else to do here?
   #@todo yes: fields!

def dispatch(dispatchable_obj):
   if args_ns.wireshark and dispatchable_obj.getTag() == Protocol.tag():
      _logger.debug('Beginning dispatch for {} protocol'.format(dispatchable_obj.name))
      folder = os.path.join(args_ns.path, dispatchable_obj.abbreviation)
      try:
         force_folder(folder)
      except ValueError as ve:
         raise DispatchError(ve)
      
      namespace = { 'enums'              : dict(),
                    'value_strings'      : dict(),
                    'true_false_strings' : dict(),
                    'fields'             : dict(),
                    'messages'           : dict()
                  }
      
      dispatch_node(dispatchable_obj, namespace)
      
      with open(os.path.join(folder, 'packet-{}.c'.format(dispatchable_obj.abbreviation)), 'w') as cfile:
         with open(os.path.join(folder, 'packet-{}.h'.format(dispatchable_obj.abbreviation)), 'w') as hfile:
            hfile.write(_ws_text['header_comment'].format(**{'filename':hfile.name, 'description':"The header file for the {} protocol".format(dispatchable_obj.name)}))
            hfile.write('#ifndef {include_guard}\n#define {include_guard}\n'.format(**{'include_guard':'{}_'.format(hfile.name.upper().replace('-','_').replace('.','_'))}))
            cfile.write(_ws_text['header_comment'].format(**{'filename':cfile.name, 'description':"The implementation file for the {} protocol".format(dispatchable_obj.name)}))
            
            hfile.write(_ws_text['header_includes'])
            cfile.write(_ws_text['source_includes'].format(name = dispatchable_obj.abbreviation))
            
            cfile.write('static int proto_{name} = -1\n'.format(name = abbr2name(dispatchable_obj.abbreviation)))
            
            for field in namespace['fields']:
               cfile.write('static int {hf} = -1;\n'.format(hf=field['hf']))
            
            for message in namespace['messages']:
               cfile.write('static gint {ett} = -1;\n'.format(ett=message['ett']))
               for group in message:
                  cfile.write('static gint {ett} = -1;\n'.format(ett=group['ett']))
            
            for enum in namespace['enums']:
               hfile.write(enum);
            for vs in namespace['value_strings']:
               hfile.write(var_decl(vs))
               cfile.write(vs)
            for tfs in namespace['true_false_strings']:
               hfile.write(var_decl(tfs))
               cfile.write(tfs)
            
            hfile.write('#endif /* {include_guard} */\n'.format(include_guard = '{}_'.format(hfile.name.upper().replace('-','_').replace('.','_'))))
            
            #@todo write out the rest of the source file
            #dissect_...
            cfile.write('{decl}\n{{\n'.format(**{'decl':dissect_fxn_decl.format(dispatchable_obj.abbreviation)}))
            # @todo
            cfile.write('}}\n')
            #proto_register...
            cfile.write('{decl}\n{{\n'.format(**{'decl':register_fxn_decl.format(dispatchable_obj.abbreviation)}))
            if len(namespace['fields']):
               cfile.write('{indent}static hf_register_info hf[] = {{\n'.format(**{'indent':_ws_text['indent']}))
               for f in namespace['fields'].values():
                  cfile.write(ws_header_field(f))
               #@todo maybe possibly also ett_ entities get hfs as well... can't remember offhand
               cfile.write('{indent}}};\n'.format(**{'indent':_ws_text['indent']})
            cfile.write('{indent}static gint *ett[] = {{\n'.format(**{'indent':_ws_text['indent']}))
            #     ... @todo
            cfile.write('{indent}}};\n'.format(**{'indent':_ws_text['indent']}))
            cfile.write('{indent}module_t *{name}_module;\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            #  /* other vars (pref_t, etc.) *
            cfile.write('{indent}proto_{name} = proto_register_protocol("{detail}, "{brief}", "{abbreviation}");\n'.format(**{'indent':_ws_text['indent'], 
                                                                                                                              'name':abbr2name(dispatchable_obj.abbreviation),
                                                                                                                              'detail':dispatchable_obj.detail,
                                                                                                                              'brief':dispatchable_obj.brief,
                                                                                                                              'abbreviation':dispatchable_obj.abbreviation
                                                                                                                              }))
            if len(namespace['fields']):
               cfile.write('{indent}proto_register_field_array(proto_{name}, hf);\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            cfile.write('{indent}proto_register_subtree_array(proto_{name}, ett, array_length(ett));\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            #  /* @todo tables, etc.*/
            cfile.write('}}\n')
            #proto_reg_handoff...
            cfile.write('{decl}\n{{\n'.format(**{'decl':handoff_fxn_decl.format(abbr2name(dispatchable_obj.abbreviation))}))
            cfile.write('{indent}dissector_handle_t {name}_handle;\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            cfile.write('{indent}{name}_handle = create_dissector_handle(dissect_{name}, proto_{name});'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            #  /* @todo reg_handoff stuff */
            cfile.write('}}\n')
