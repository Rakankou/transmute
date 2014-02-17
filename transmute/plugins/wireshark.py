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

__all__  = ["register", "Register", "Expose", "dispatch"]

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

class Expose(Parsable):
   def __init__(self):
      super().__init__()
      self.field = ''
   
   def tag():
      return ':'.join([_prefix, 'expose']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      if args_ns.ws:
         try:
            self.field = attrs['field']
         except KeyError as ki:
            raise ParseError("{} missing required attribute '{}'".format(self.getTag(), ki))
   
   def End(self):
      pass #ws:expose does not have complex ending tasks
   
   def Cdata(self, data):
      pass #ws:expose does not have cdata
   
   def Child(self, child):
      pass #ws:expose does not have child nodes
   
   def Validate(self, parent):
      super().Validate(parent)
      if parent.getTag() == Protocol.tag():
         if not parent.hasField(self.field):
            raise ValidationError("<{}> uses unknown field '{}'".format(self.getTag(), self.field))
      else:
         raise ValidationError("<{slf}> under <{p}>. <{slf}> can only be given under <{proto}>".format(slf=self.getTag(), p=parent.getTag(), proto=Protocol.tag()))

def register(args_parser, xml_parser):
   global args_ns
   args_group = args_parser.add_argument_group(title='wireshark', description='These arguments control the wireshark output.')
   args_group.add_argument('-ws', '--wireshark',      action='store_true', default=False,                 help="Enable wireshark output.")
   args_group.add_argument('-wso', '--wireshark-out', default='.',         type=folder_type, dest='path', help="Change the wireshark output folder (default is the current working directory).")
   args_ns,argv = args_parser.parse_known_args()
   for parsable in [Register,
                    Expose
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
             'header_field'      : '''{indent}{{&hf_{name},\n{indent}{indent}{{"{brief}", "{abbreviation}", FT_{ftype}, BASE_{btype}, {VALS}, {mask},\n{indent}{indent}{indent}"{detail}", HFILL}}}},\n''',
           }

_ws_ftypes = {'undecoded'         : 'NONE',
              'bool'              : 'BOOLEAN',
              'boolean'           : 'BOOLEAN',
              'enum'              : 'UINT',
              'enumeration'       : 'UINT',
              'weighted'          : 'DOUBLE',
              'unsigned weighted' : 'DOUBLE',
              'float'             : 'FLOAT',
              'double'            : 'DOUBLE',
              'int'               : 'INT',
              'integer'           : 'INT',
              'unsigned int'      : 'UINT',
              'unsigned integer'  : 'UINT'
             }

##
# @brief Translates an abbreviation string to a name string.
# @param abbreviation [in] The abbreviation string.
# @return The name string suitable for use as or within a C identifier.
def abbr2name(abbreviation):
   return abbreviation.replace('.','_').replace('-','_')

def ws_field_ftype(f):
   ftype = _ws_ftypes[f.ftype]
   if 'INT' in ftype:
      bitlength = f.bitlength()
      if   1  <= bitlength <= 8:
         ftype = ''.join((ftype, '8'))
      elif       bitlength <= 16:
         ftype = ''.join((ftype, '16'))
      elif       bitlength <= 24:
         ftype = ''.join((ftype, '24'))
      elif       bitlength <= 32:
         ftype = ''.join((ftype, '32'))
      else:
         raise DispatchError("<{}> with unsupported bit length {}".format(f.getTag(), bitlength))
   return ftype

def ws_field_basetype(f):
   bitlength = f.bitlength()
   if 'INT' in ftype:
      if   bitlength % 4 == 0:
         return 'HEX'
      elif bitlength % 3 == 0:
         return 'OCT'
      else:
         return 'DEC'
   else:
      return 'NONE'

def ws_header_field(f, namespace):
   attrs = {'indent'      : _ws_text['indent'],
            'name'        : abbr2name(f.description.abbreviation),
            'brief'       : f.description.brief,
            'abbreviation': f.description.abbreviation,
            'ftype'       : _ws_ftypes[f.ftype if hasattr(f, 'ftype') else 'undecoded'],
            'btype'       : 'NONE',
            'VALS'        : 'NULL',
            'mask'        : '0x0',
            'detail'      : f.description.detail
           }
   
   attrs['ftype'] = ws_field_ftype(f)
   attrs['btype'] = ws_field_basetype(f)
   
   if f.ftype[:4] == 'enum':
      attrs['VALS'] = 'VALS({vstr}_{vname})'.format(**{'vstr' : 'tfs' if is_tfs(f.values) else 'vs',
                                                       'vname': f.values.name if f.values.name else abbr2name(f.description.abbreviation)
                                                      })
   if f.bitstart or f.bitlength % f.chunksize:
      mask = hex(f.bitmask)
   
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

def write_dissect_fxn(dispatchable_obj, cfile):
   header  = hasattr(dispatchable_obj, 'header')  and dispatchable_obj.header is not None
   if header:
      for TODO in header.TODO:
         write_dissect_fxn(header.TODO.TODO, cfile)
   trailer = hasattr(dispatchable_obj, 'trailer') and dispatchable_obj.header is not None
   if trailer:
      for TODO in trailer.TODO:
         write_dissect_fxn(trailer.TODO.TODO, cfile)
   
   cfile.write('{decl}\n{{\n'.format(**{'decl':dissect_fxn_decl.format(dispatchable_obj.abbreviation)}))
   cfile.write('\n'.join(['{indent}gint32       value = 0;',
                          '{indent}tvbuff_t    *tvbr  = NULL;',
                          '{indent}proto_item  *pItem = NULL;',
                          '{indent}proto_tree  *pTree = NULL;'
                         ]).format(indent = _ws_text['indent'],
                                   name   = abbr2name(dispatchable_obj.abbreviation)
                                  ))
   
   cfile.write('{indent}col_set_str(pinfo->cinfo, COL_PROTOCOL, "{name}");\n'.format(indent = _ws_text['indent'],
                                                                                     name   = dispatchable_obj.description.brief
                                                                                    ))
   cfile.write('{indent}pItem = proto_tree_add_item(   tree, proto_{name}, tvb, 0, -1, ENC_{endian}_ENDIAN);\n'.format(indent = _ws_text['indent'],
                                                                                                                         name   = abbr2name(dispatchable_obj.abbreviation),
                                                                                                                         endian = "BIG" if dispatchable_obj.endian == Constants.endian['big'] else "LITTLE"
                                                                                                                        ))
   cfile.write('{indent}pTree = proto_item_add_subtree(pItem, ett_{name});\n'.format(indent = _ws_text['indent'],
                                                                                     name   = abbr2name(dispatchable_obj.abbreviation)
                                                                                    ))
   if header
      cfile.write('{indent}tvbr = tvbuff_new_subset(tvb, 0, {length}, {length});\n'.format(indent = _ws_text['indent']
                                                                                           length = TODO
                                                                                          ))
      #@todo
   # @todo
   if hasattr(self, 'groups'):
      pass #@todo
   if hasattr(self, 'fields'):
      pass #@todo
   if hasattr(self, 'messages'):
      pass #@todo
   #     weighted use proto_tree_add_double_format_value
   if trailer
      pass #@todo
   cfile.write('}}\n')

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
   if   dispatchable_obj.getTag() == Field.tag():
      if dispatchable_obj.abbreviation in namespace['fields']:
         raise DispatchError("More than one field with name {name}".format(name = dispatchable_obj.abbreviation))
      namespace['fields'][dispatchable_obj.abbreviation] = dispatchable_obj
   elif dispatchable_obj.getTag() == Message.tag():
      if dispatchable_obj.abbreviation in namespace['messages']:
         raise DispatchError("More than one message with name {name}".format(name = dispatchable_obj.abbreviation))
      if dispatchable_obj.abbreviation in namespace['trees']:
         raise DispatchError("More than one tree with name {name}".format(name = dispatchable_obj.abbreviation)
      namespace['messages'][dispatchable_obj.abbreviation] = dispatchable_obj
      namespace['trees'][dispatchable_obj.abbreviation] = dispatchable_obj
   elif dispatchable_obj.getTag() == Group.tag():
      if dispatchable_obj.abbreviation in namespace['trees']:
         raise DispatchError("More than one tree with name {name}".format(name = dispatchable_obj.abbreviation)
      namespace['trees'][dispatchable_obj.abbreviation] = dispatchable_obj
   pass #@todo any other objects that need to be added to the tree

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
                    'messages'           : dict(),
                    'trees'              : dict(),
                    'tables'             : dict(),
                    'joins'              : dict()
                  }
      
      dispatch_node(dispatchable_obj, namespace)
      for child in dispatchable_obj.children:
         if   child.getTag() == Expose.tag():
            if child.field in namespace['tables']:
               raise DispatchError("More than one <{}> with name '{}'".format(Expose.tag(), child.field))
            if not dispatchable_obj.hasField(child.field):
               raise DispatchError("<{}> specifies unavailable field '{}'".format(Expose.tag(), child.field))
            namespace['tables'][child.field] = child
         elif child.getTag() == Register.tag():
            if child.table not in namespace['joins']:
               namespace['joins'][child.table] = list()
            namespace['joins'][child.table].append(child)
      
      with open(os.path.join(folder, 'packet-{}.c'.format(dispatchable_obj.abbreviation)), 'w') as cfile:
         with open(os.path.join(folder, 'packet-{}.h'.format(dispatchable_obj.abbreviation)), 'w') as hfile:
            hfile.write(_ws_text['header_comment'].format(**{'filename':hfile.name, 'description':"The header file for the {} protocol".format(dispatchable_obj.name)}))
            hfile.write('#ifndef {include_guard}\n#define {include_guard}\n'.format(**{'include_guard':'{}_'.format(hfile.name.upper().replace('-','_').replace('.','_'))}))
            cfile.write(_ws_text['header_comment'].format(**{'filename':cfile.name, 'description':"The implementation file for the {} protocol".format(dispatchable_obj.name)}))
            
            hfile.write(_ws_text['header_includes'])
            cfile.write(_ws_text['source_includes'].format(name = dispatchable_obj.abbreviation))
            
            cfile.write('static int proto_{name} = -1\n'.format(name = abbr2name(dispatchable_obj.abbreviation)))
            
            for field in namespace['fields']:
               cfile.write('static int hf_{hf} = -1;\n'.format(hf=abbr2name(field.abbreviation)))
            
            for tree in namespace['trees']:
               cfile.write('static gint ett_{ett} = -1;\n'.format(ett=abbr2name(tree.abbreviation)))
            
            for enum in namespace['enums']:
               hfile.write(enum);
            for vs in namespace['value_strings']:
               hfile.write(var_decl(vs))
               cfile.write(vs)
            for tfs in namespace['true_false_strings']:
               hfile.write(var_decl(tfs))
               cfile.write(tfs)
            
            hfile.write('#endif /* {include_guard} */\n'.format(include_guard = '{}_'.format(hfile.name.upper().replace('-','_').replace('.','_'))))
            
            #dissect_...
            write_dissect_fxn(dispatchable_obj, cfile);
            #proto_register...
            cfile.write('{decl}\n{{\n'.format(**{'decl':register_fxn_decl.format(dispatchable_obj.abbreviation)}))
            if len(namespace['fields']):
               cfile.write('{indent}static hf_register_info hf[] = {{\n'.format(**{'indent':_ws_text['indent']}))
               for f in namespace['fields'].values():
                  cfile.write(ws_header_field(f, namespace))
               cfile.write('{indent}}};\n'.format(**{'indent':_ws_text['indent']})
            cfile.write('{indent}static gint *ett[] = {{\n'.format(**{'indent':_ws_text['indent']}))
            for t in namespace['trees']:
               cfile.write('{indent}{indent}&ett_{ett}'.format(**{'indent':_ws_text['indent'], 'ett':abbr2name(t.abbreviation)}))
            cfile.write('{indent}}};\n'.format(**{'indent':_ws_text['indent']}))
            cfile.write('{indent}dissector_handle_t {name}_handle;\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            cfile.write('{indent}{name}_handle = create_dissector_handle(dissect_{name}, proto_{name});'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            cfile.write('{indent}module_t *{name}_module;\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            #  /* other vars (pref_t, etc.) */
            cfile.write('{indent}proto_{name} = proto_register_protocol("{detail}, "{brief}", "{abbreviation}");\n'.format(**{'indent'       : _ws_text['indent'], 
                                                                                                                              'name'         : abbr2name(dispatchable_obj.abbreviation),
                                                                                                                              'detail'       : dispatchable_obj.detail,
                                                                                                                              'brief'        : dispatchable_obj.brief,
                                                                                                                              'abbreviation' : dispatchable_obj.abbreviation
                                                                                                                              }))
            if len(namespace['fields']):
               cfile.write('{indent}proto_register_field_array(proto_{name}, hf);\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            cfile.write('{indent}proto_register_subtree_array(proto_{name}, ett, array_length(ett));\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
            for table in namespace['tables']:
               field = dispatchable_obj.getField(table.field)
               cfile.write('{indent}register_dissector_table("{field}", "{descr}", FT_{ftype}, BASE_{btype});\n'.format(indent = _ws_text['indent'],
                                                                                                                        field  = table.field,
                                                                                                                        descr  = field.brief,
                                                                                                                        ftype  = ws_field_ftype(field),
                                                                                                                        btype  = ws_field_basetype(field)
                                                                                                                       ))
            cfile.write('}}\n')
            #proto_reg_handoff...
            cfile.write('{decl}\n{{\n'.format(**{'decl':handoff_fxn_decl.format(abbr2name(dispatchable_obj.abbreviation))}))
            cfile.write('{indent}dissector_handle_t {name}_handle = find_dissector("{name}");\n'.format(indent = _ws_text['indent'], name=abbr2name(dispatchable_obj.abbreviation)))
            for join in namespace['joins']:
               for r in join:
                  cfile.write('{indent}dissector_add("{table}", {value}, {name}_handle);\n"'.format(indent = _ws_text[indent],
                                                                                                    table  = r.table,
                                                                                                    value  = r.value,
                                                                                                    name   = abbr2name(dispatchable_obj.abbreviation)))
            # /* @todo register other dissectors against own tables */
            cfile.write('}}\n')
