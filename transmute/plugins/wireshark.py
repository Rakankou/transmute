##
# @file transmute/plugins/wireshark.py
# @brief Contains the Wireshark Dissector generation code.
# @ingroup plugins
#

import logging
import os
from   argparse                import ArgumentTypeError
from   sys                     import argv
from   collections             import OrderedDict
from   ..                      import version_string as transmute_version
from   ..Parsing.Parsable      import Parsable
from   ..Parsing.Parser        import ParseError
from   .base                   import *
from   ..Dispatch.Dispatchable import Dispatchable, DispatchError

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
   return path

def folder_type(path):
   try:
      return force_folder(path)
   except ValueError as ve:
      raise ArgumentTypeError(ve)

##
# @name Register
# @brief An element to register against a Wireshark dissector table.
# @details XML tag: ws:register
#          Attributes: table, value
#             table (required) - The table identifier string.
#             value (required) - The value to register against
#          CData: none
#          Children: none
#          Parents: protocol, message
class Register(Parsable):
   def __init__(self):
      super().__init__()
      self.table = ''
      self.value = ''
   
   def tag():
      return ':'.join([_prefix, 'register']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      if args_ns.wireshark:
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

##
# @name Expose
# @brief An element to expose a dissector table.
# @details XML tag: ws:expose
#          Attributes: field
#             field (required) - The field abbreviation to expose.
#          CData: none
#          Children: none
#          Parents: protocol, message
class Expose(Parsable):
   def __init__(self):
      super().__init__()
      self.field = ''
   
   def tag():
      return ':'.join([_prefix, 'expose']).lstrip(':')
   
   def Start(self, attrs, evt_stream, node, parser):
      if args_ns.wireshark:
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
   args_group.add_argument(        '--wireshark-out',                      type=folder_type, dest='path', help="Change the wireshark output folder (default is the current working directory).")
   args_ns,argv = args_parser.parse_known_args()
   for parsable in [Register,
                    Expose
                   ]:
      xml_parser.registerParsable(parsable)


_ws_text = { 'header_comment'    : "/* \n * File: {{filename}}\n * Description: {{description}}\n * Generated using transmute {transmute_version} Wireshark plugin {plugin_version}\n */\n".format(**{'transmute_version':transmute_version,'plugin_version':version_string}),
             'header_includes'   : '\n'.join(['#include "config.h"',
                                              '#include <glib.h>',
                                              '#include <epan/packet.h>',
                                              '#include <epan/proto.h>',
                                              '#include <epan/tvbuff.h>',
                                              '#include <epan/column-utils.h>',
                                              ''
                                            ]),
             'source_includes'   : "#include \"packet-{name}.h\"\n",
             'enum'              : "typedef enum enum_{name} {{\n{values}\n}} {name};\n",
             'enum_value'        : "{indent}{name} = {value}",
             'vs_value'          : "{indent}{{{name}, \"{name}\"}}",
             'value_string'      : "const value_string vs_{name}[] = {{\n{values},\n{indent}{{0, NULL}}\n}};\n",
             'true_false_string' : "const true_false_string tfs_{name} = {{{vtrue}, {vfalse}}};\n",
             'dissect_fxn_decl'  : "static void dissect_{name}(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)",
             'dissect_fxn_vars'  : "int offset = 0;\n   proto_tree *{name}_tree;\n   proto_item *pItem;\n",
             'dissect_fxn_cols'  : "col_set_str(pinfo->cinfo, COL_PROTOCOL, \"{name}\");\n   col_clear(pinfo->cinfo, COL_INFO);\n",
             'register_fxn_decl' : "void proto_register_{name}(void)",
             'handoff_fxn_decl'  : "void proto_reg_handoff_{name}(void)",
             'handoff_fxn_vars'  : "dissector_handle_t {name}_handle;\n",
             'indent'            : "   ",
             'header_field'      : '''{indent}{{&hf_{name},\n{indent}{indent}{{"{brief}", "{abbreviation}", FT_{ftype}, BASE_{btype}, {VALS}, {mask},\n{indent}{indent}{indent}"{detail}", HFILL}}}}''',
           }

_ws_ftypes = {'undecoded'         : 'NONE',
              'bool'              : 'BOOLEAN',
              'boolean'           : 'BOOLEAN',
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

##
# @brief Translates an abbreviation string to a name string.
# @param abbreviation [in] The abbreviation string.
# @return The name string suitable for use as or within a C identifier.
def abbr2name(abbreviation):
   return abbreviation.replace('.','_').replace('-','_')

def ws_chunks2bytes(chunksize, i):
   if chunksize % 8 or chunksize <= 0:
      raise ValueError(chunksize)
   return int(round(i * (chunksize / 8), 0))

def ws_has_section(dispatchable_obj, section):
   return hasattr(dispatchable_obj, section) and getattr(dispatchable_obj, section) is not None

def ws_field_ftype(f):
   ftype = _ws_ftypes[f.ftype if ws_has_section(f, 'ftype') else 'undecoded']
   if 'INT' in ftype:
      bitlength = f.position.bitlength
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

def ws_field_size(f):
   field_type = ws_field_ftype(f)
   if   (('FLOAT' in field_type) or
         ('INT32' in field_type)):
      return 4
   elif 'INT16' in field_type:
      return 2
   elif 'INT8' in field_type:
      return 1
   elif 'DOUBLE' in field_type:
      return 8
   return ws_chunks2bytes(f.chunksize, f.position.chunklength)

def ws_field_basetype(f):
   bitlength = f.position.bitlength
   ftype = _ws_ftypes[f.ftype if ws_has_section(f, 'ftype') else 'undecoded']
   if 'INT' in ftype:
      if   bitlength % 4 == 0:
         return 'HEX'
      elif bitlength % 3 == 0:
         return 'OCT'
      else:
         return 'DEC'
   else:
      return 'NONE'

def ws_header_field(f):
   attrs = {'indent'      : _ws_text['indent'],
            'name'        : abbr2name(f.description.abbreviation),
            'brief'       : f.description.brief,
            'abbreviation': f.description.abbreviation,
            'ftype'       : _ws_ftypes[f.ftype if hasattr(f, 'ftype') else 'undecoded'],
            'btype'       : 'NONE',
            'VALS'        : 'NULL',
            'mask'        : 0x0,
            'detail'      : f.description.detail
           }
   
   attrs['ftype'] = ws_field_ftype(f)
   attrs['btype'] = ws_field_basetype(f)
   
   if isinstance(f, Field) and attrs['ftype'] != 'NONE':
      if 'enum' in f.ftype:
         attrs['VALS'] = 'VALS({vstr}_{vname})'.format(vstr  = 'tfs' if is_tfs(f.values) else 'vs',
                                                       vname = f.values.name if f.values.name else abbr2name(f.description.abbreviation)
                                                      )
      attrs['mask'] = hex(f.position.bitmask)
      if((attrs['ftype'] == 'DOUBLE' and attrs['mask'] == '0xffffffffffffffff') or
         (attrs['ftype'] == 'FLOAT'  and attrs['mask'] == '0xffffffff'        ) or
         ('INT32' in attrs['ftype']  and attrs['mask'] == '0xffffffff'        ) or
         ('INT16' in attrs['ftype']  and attrs['mask'] == '0xffff'            ) or
         ('INT8'  in attrs['ftype']  and attrs['mask'] == '0xff'              )):
         attrs['mask'] = 0
   
   return '{indent}{s}'.format(indent = _ws_text['indent'],
                               s      = _ws_text['header_field'].format(**attrs))

def ws_include_guard(file_obj):
   return os.path.basename('{}_'.format(file_obj.name.upper().replace('-','_').replace('.','_')))

def is_tfs(e):
   return (len(e) == 2) and (tuple(e.values[k] for k in e.values) in [(0,1), (1,0)])

def tfs_get(v, val):
   if not is_tfs(v):
      raise DispatchError("{} is not a true_false_string".format(v.name))
   for k in v.values.keys():
      if v.values[k] == val:
         return k

def var_decl(v):
   _logger.debug('ws:var_decl({})'.format(v))
   return '{}\n'.format(''.join((v[:v.index('=')].rstrip(),';')))

def write_dissect_fxn(dispatchable_obj, cfile):
   if ws_has_section(dispatchable_obj, 'header'):
      write_dissect_fxn(dispatchable_obj.header, cfile)
   if ws_has_section(dispatchable_obj, 'trailer'):
      write_dissect_fxn(dispatchable_obj.trailer, cfile)
   if ws_has_section(dispatchable_obj, 'messages'):
      for msg in dispatchable_obj.messages:
         write_dissect_fxn(dispatchable_obj.messages[msg], cfile)
   cfile.write('{decl}\n{{\n'.format(**{'decl':_ws_text['dissect_fxn_decl'].format(name=abbr2name(dispatchable_obj.abbreviation))}))
   cfile.write('\n'.join(['{indent}gint32            value  = 0;',
                          '{indent}tvbuff_t         *tvbr   = NULL;',
                          '{indent}proto_item       *pItem  = NULL;',
                          '{indent}proto_tree       *pTree  = NULL;',
                          '{indent}proto_item       *psubI  = NULL;',
                          '{indent}proto_tree       *psubT  = NULL;',
                          '{indent}dissector_table_t pTable = NULL;\n'
                         ]).format(indent = _ws_text['indent'],
                                   name   = abbr2name(dispatchable_obj.abbreviation)
                                  ))
   if not isinstance(dispatchable_obj, (Header, Trailer)):
      cfile.write('{indent}col_set_str(pinfo->cinfo, COL_PROTOCOL, "{name}{space}");\n'.format(indent = _ws_text['indent'],
                                                                                               name   = dispatchable_obj.description.name,
                                                                                               space  = ' ' if isinstance(dispatchable_obj, Protocol) else ''
                                                                                              ))
      if isinstance(dispatchable_obj, Protocol):
         cfile.write('{indent}col_set_fence(pinfo->cinfo, COL_PROTOCOL);\n'.format(indent = _ws_text['indent']))
   cfile.write('{indent}pItem = proto_tree_add_item(   tree, {proto_or_hf}_{name}, tvb, {offset}, {length}, ENC_{endian}_ENDIAN);\n'.format(indent = _ws_text['indent'],
                                                                                                                         name   = abbr2name(dispatchable_obj.abbreviation),
                                                                                                                         endian = "BIG" if dispatchable_obj.endian == Constants.endian['big'] else "LITTLE",
                                                                                                                         proto_or_hf = "proto" if dispatchable_obj.getTag() == Protocol.tag() else "hf",
                                                                                                                         length = ws_chunks2bytes(dispatchable_obj.position.chunksize, dispatchable_obj.position.chunklength),
                                                                                                                         offset = dispatchable_obj.position.index
                                                                                                                        ))
   cfile.write('{indent}pTree = proto_item_add_subtree(pItem, ett_{name});\n'.format(indent = _ws_text['indent'],
                                                                                     name   = abbr2name(dispatchable_obj.abbreviation)
                                                                                    ))
   if ws_has_section(dispatchable_obj, 'header'):
      cfile.write('{indent}dissect_{name}(tvb, pinfo, pTree);\n'.format(name = abbr2name(dispatchable_obj.header.abbreviation), indent = _ws_text['indent']))
   if ws_has_section(dispatchable_obj, 'fields'):
      for f in dispatchable_obj.fields.values():
         if f.ftype in ('weighted', 'unsigned weighted'):
            sz = ws_field_size(f)
            cfile.write('{indent}value = tvb_get_bits32(tvb, {bitoffs}, {bitlen}, {enc});\n'.format(indent  = _ws_text['indent'],
                                                                                                    bitoffs = f.position.bitstart + (f.position.chunksize * f.position.index),
                                                                                                    bitlen  = f.position.bitlength,
                                                                                                    enc     = "ENC_LITTLE_ENDIAN" if f.endian == Constants.endian['little'] else "ENC_BIG_ENDIAN"
                                                                                                   ))
            if   sz == 2:
               cfile.write('{indent}value = ntohs(value);\n'.format(indent = _ws_text['indent']))
            elif sz == 4:
               cfile.write('{indent}value = ntohl(value);\n'.format(indent = _ws_text['indent']))
            cfile.write('{indent}proto_tree_add_{unsigned}int_format_value(pTree, hf_{name}, tvb, {byteoffset}, {bytelength}, value, "(%{fmt}) %f", ((float)(value * {scale})) + ((float){voffset}));\n'.format(indent     = _ws_text['indent'],
                                                                                                                                                                                                                name       = abbr2name(f.description.abbreviation),
                                                                                                                                                                                                                endian     = "BIG" if f.endian == Constants.endian['big'] else "LITTLE",
                                                                                                                                                                                                                bytelength = ws_chunks2bytes(f.position.chunksize, f.position.chunklength),
                                                                                                                                                                                                                byteoffset = ws_chunks2bytes(f.position.chunksize, f.position.index),
                                                                                                                                                                                                                scale      = f.weight.lsb,
                                                                                                                                                                                                                voffset    = f.weight.offset,
                                                                                                                                                                                                                unsigned   = 'u' if 'unsigned' in f.ftype else '',
                                                                                                                                                                                                                fmt        = 'l' if 'unsigned' in f.ftype else 'd'
                                                                                                                                                                                                               ))
         else:
            cfile.write('{indent}proto_tree_add_item(pTree, hf_{name}, tvb, {offset}, {length}, ENC_{endian}_ENDIAN);\n'.format(indent = _ws_text['indent'],
                                                                                                                                name   = abbr2name(f.description.abbreviation),
                                                                                                                                endian = "BIG" if f.endian == Constants.endian['big'] else "LITTLE",
                                                                                                                                length = ws_chunks2bytes(f.position.chunksize, f.position.chunklength),
                                                                                                                                offset = f.position.index
                                                                                                                               ))
   if ws_has_section(dispatchable_obj, 'messages'):
      cfile.write('{indent}value = tvb_length(tvb);\n'.format(indent = _ws_text['indent']))
      if ws_has_section(dispatchable_obj, 'header'):
         cfile.write('{indent}value -= {length}; //header length\n'.format(indent = _ws_text['indent'], length = ws_chunks2bytes(dispatchable_obj.header.position.chunksize, dispatchable_obj.header.position.chunklength)))
      if ws_has_section(dispatchable_obj, 'trailer'):
         cfile.write('{indent}value -= {length}; //trailer length\n'.format(indent = _ws_text['indent'], length = ws_chunks2bytes(dispatchable_obj.trailer.position.chunksize, dispatchable_obj.trailer.position.chunklength)))
      cfile.write('{indent}tvbr = tvb_new_subset(tvb, {offset}, value, value);\n'.format(indent = _ws_text['indent'],
                                                                                            offset = ws_chunks2bytes(dispatchable_obj.header.position.chunksize, dispatchable_obj.header.position.chunklength) if ws_has_section(dispatchable_obj, 'header') else 0
                                                                                           ))
      for table in (c for c in dispatchable_obj.children if isinstance(c, Expose)):
         cfile.write('{indent}pTable = find_dissector_table("{name}");\n'.format(indent = _ws_text['indent'],
                                                                                 name   = table.field
                                                                                ))
         tfield = dispatchable_obj.getField(table.field)
         cfile.write('{indent}value = tvb_get_bits32(tvb, {bitoffs}, {bitlen}, {enc});\n'.format(indent  = _ws_text['indent'],
                                                                                                 bitoffs = tfield.position.bitstart + (tfield.position.chunksize * tfield.position.index),
                                                                                                 bitlen  = tfield.position.bitlength,
                                                                                                 enc     = "ENC_LITTLE_ENDIAN" if tfield.endian == Constants.endian['little'] else "ENC_BIG_ENDIAN"
                                                                                                ))
         cfile.write('{indent}if(pTable)\n{indent}{{\n{indent}{indent}dissector_try_uint(pTable, value, tvbr, pinfo, pTree);\n{indent}}}\n'.format(indent = _ws_text['indent']))
   if ws_has_section(dispatchable_obj, 'trailer'):
      cfile.write('{indent}dissect_{name}(tvb, pinfo, pTree);\n'.format(indent = _ws_text['indent'],
                                                                        name   = abbr2name(dispatchable_obj.trailer.abbreviation)
                                                                       ))
   cfile.write('}\n\n')

def write_register_fxn(dispatchable_obj, cfile):
   cfile.write('{decl}\n{{\n'.format(**{'decl':_ws_text['register_fxn_decl'].format(name=abbr2name(dispatchable_obj.abbreviation))}))
   if dispatchable_obj.hasFields():
      cfile.write('{indent}static hf_register_info hf[] = {{'.format(**{'indent':_ws_text['indent']}))
      header_fields = ''
      if ws_has_section(dispatchable_obj, 'header'):
         header_fields = ',\n'.join([header_fields, ws_header_field(dispatchable_obj.header)])
         header_fields = ',\n'.join([header_fields, ',\n'.join(ws_header_field(f) for f in dispatchable_obj.header.fields.values())])
      if ws_has_section(dispatchable_obj, 'fields'):
         header_fields = ',\n'.join([header_fields, ',\n'.join(ws_header_field(f) for f in dispatchable_obj.fields.values())])
      if ws_has_section(dispatchable_obj, 'trailer'):
         header_fields = ',\n'.join([header_fields, ws_header_field(dispatchable_obj.trailer)])
         header_fields = ',\n'.join([header_fields, ',\n'.join(ws_header_field(f) for f in dispatchable_obj.trailer.fields.values())])
      if isinstance(dispatchable_obj, Message):
         header_fields = ',\n'.join([header_fields, ws_header_field(dispatchable_obj)])
      cfile.write(header_fields.lstrip(','))
      cfile.write('\n{indent}}};\n'.format(**{'indent':_ws_text['indent']}))
   cfile.write('{indent}static gint *ett[] = {{\n'.format(**{'indent':_ws_text['indent']}))
   cfile.write('{indent}{indent}&ett_{ett}'.format(**{'indent':_ws_text['indent'], 'ett':abbr2name(dispatchable_obj.abbreviation)}))
   if ws_has_section(dispatchable_obj, 'header'):
      cfile.write(',\n{indent}{indent}&ett_{ett}'.format(**{'indent':_ws_text['indent'], 'ett':abbr2name(dispatchable_obj.header.abbreviation)}))
   if ws_has_section(dispatchable_obj, 'trailer'):
      cfile.write(',\n{indent}{indent}&ett_{ett}'.format(**{'indent':_ws_text['indent'], 'ett':abbr2name(dispatchable_obj.trailer.abbreviation)}))
   cfile.write('\n{indent}}};\n'.format(**{'indent':_ws_text['indent']}))
   #note: the module_t* variables are needed for protocol preferences and other items we don't support yet
   #cfile.write('{indent}module_t *module_{name};\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
   cfile.write('{indent}proto_{name} = proto_register_protocol("{protoname}", "{brief}", "{abbreviation}");\n'.format(indent       = _ws_text['indent'], 
                                                                                                                      name         = abbr2name(dispatchable_obj.abbreviation),
                                                                                                                      protoname    = dispatchable_obj.description.name,
                                                                                                                      brief        = dispatchable_obj.description.brief,
                                                                                                                      abbreviation = dispatchable_obj.description.abbreviation
                                                                                                                     ))
   cfile.write('{indent}handle_{name} = create_dissector_handle(dissect_{name}, proto_{name});\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
   if dispatchable_obj.hasFields():
      cfile.write('{indent}proto_register_field_array(proto_{name}, hf, array_length(hf));\n'.format(**{'indent':_ws_text['indent'], 'name':abbr2name(dispatchable_obj.abbreviation)}))
   cfile.write('{indent}proto_register_subtree_array(ett, array_length(ett));\n'.format(**{'indent':_ws_text['indent']}))
   for table in (c for c in dispatchable_obj.children if isinstance(c, Expose)):
      field = dispatchable_obj.getField(table.field)
      cfile.write('{indent}register_dissector_table("{field}", "{descr}", FT_{ftype}, BASE_{btype});\n'.format(indent = _ws_text['indent'],
                                                                                                               field  = table.field,
                                                                                                               descr  = field.description.brief,
                                                                                                               ftype  = ws_field_ftype(field),
                                                                                                               btype  = ws_field_basetype(field)
                                                                                                              ))
   cfile.write('}\n\n')
   if ws_has_section(dispatchable_obj, 'messages'):
      for m in dispatchable_obj.messages.values():
         write_register_fxn(m, cfile)

def write_handoff_fxn(dispatchable_obj, cfile, local_handles):
   cfile.write('{decl}\n{{\n'.format(**{'decl':_ws_text['handoff_fxn_decl'].format(name=abbr2name(dispatchable_obj.abbreviation))}))
   _local_handles = ['handle_{name}'.format(name = abbr2name(l.abbreviation)) for l in local_handles.values()]
   handles = set()
   joins = [j for j in dispatchable_obj.children if isinstance(j, Register)]
   for j in joins:
      handles.add('handle_{name}'.format(name = abbr2name(j.parent.abbreviation)))
   for h in handles:
      if h not in _local_handles:
         cfile.write('{indent}dissector_handle_t {handle};\n'.format(indent = _ws_text['indent'], handle = h))
   for j in joins:
      if h not in _local_handles:
         cfile.write('{indent}handle_{name} = find_dissector("{name}");\n'.format(indent = _ws_text['indent'], name=abbr2name(j.parent.abbreviation)))
      cfile.write('{indent}dissector_add_uint("{table}", {value}, handle_{name});\n'.format(indent = _ws_text['indent'],
                                                                                            table  = j.table,
                                                                                            value  = j.value,
                                                                                            name   = abbr2name(j.parent.abbreviation)))
   cfile.write('}\n\n')
   if ws_has_section(dispatchable_obj, 'messages'):
      for m in dispatchable_obj.messages.values():
         write_handoff_fxn(m, cfile, local_handles)

def write_cmake_file(folder, dispatchable_obj):
   with open(os.path.join(folder, 'CMakeLists.txt'), 'w') as cmakefile:
      cmakefile.write('\n'.join(['# This file automatically generated using Transmute',
                                 'set(DISSECTOR_SRC',
                                 '\tpacket-{}.c'.format(dispatchable_obj.abbreviation),
                                 ')',
                                 '',
                                 'set(PLUGIN_FILES',
                                 '\tplugin.c',
                                 '\t${PLUGIN_FILES}',
                                 ')',
                                 '',
                                 'set(CLEAN_FILES',
                                 '\t${PLUGIN_FILES}',
                                 ')',
                                 '',
                                 'if (WERROR)',
                                 '\tset_source_files_properties(',
                                 '\t\t${CLEAN_FILES}',
                                 '\t\tPROPERTIES',
                                 '\t\tCOMPILE_FLAGS -Werror',
                                 '\t)',
                                 'endif()',
                                 '',
                                 'include_directories(${CMAKE_CURRENT_SOURCE_DIR})',
                                 '',
                                 'register_dissector_files(plugin.c',
                                 '\tplugin',
                                 '\t${DISSECTOR_SRC}',
                                 ')',
                                 '',
                                 'add_library({} ${{LINK_MODE_MODULE}}'.format(dispatchable_obj.abbreviation),
                                 '\t${PLGUIN_FILES}',
                                 ')',
                                 'set_target_properties({} PROPERTIES PREFIX "")'.format(dispatchable_obj.abbreviation),
                                 'set_target_properties({} PROPERTIES LINK_FLAGS "${{WS_LINK_FLAGS}}")'.format(dispatchable_obj.abbreviation),
                                 '',
                                 'target_link_libraries({} epan)'.format(dispatchable_obj.abbreviation),
                                 '',
                                 'install(TARGETS {}'.format(dispatchable_obj.abbreviation),
                                 '\tLIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP',
                                 '\tRUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}',
                                 '\tARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}',
                                 ')',
                                 '']
                     ))
   
def write_moduleinfo_file(folder, dispatchable_obj):
   vinfo = dispatchable_obj.version.data
   for k in ['major', 'minor', 'micro', 'extra']:
      try:
         int(vinfo[k])
      except KeyError as ke:
         _logger.info('<{}> {} version is missing {}, using default'.format(dispatchable_obj.getTag(), dispatchable_obj.name, ke))
         vinfo[k] = '0'
      except ValueError as ve:
         _logger.info('<{}> {} version is missing {}, using default'.format(dispatchable_obj.getTag(), dispatchable_obj.name, ve))
         vinfo[k] = '0'
   with open(os.path.join(folder, 'moduleinfo.nmake'), 'w') as mfile:
      mfile.write('\n'.join(['# This file automatically generated using Transmute',
                             'PACKAGE={}'.format(dispatchable_obj.abbreviation),
                             'MODULE_VERSION_MAJOR={}'.format(dispatchable_obj.version.data['major']),
                             'MODULE_VERSION_MINOR={}'.format(dispatchable_obj.version.data['minor']),
                             'MODULE_VERSION_MICRO={}'.format(dispatchable_obj.version.data['micro']),
                             'MODULE_VERSION_EXTRA={}'.format(dispatchable_obj.version.data['extra']),
                             'MODULE_VERSION=$(MODULE_VERSION_MAJOR).$(MODULE_VERSION_MINOR).$(MODULE_VERSION_MICRO).$(MODULE_VERSION_EXTRA)',
                             'RC_MODULE_VERSION=$(MODULE_VERSION_MAJOR),$(MODULE_VERSION_MINOR),$(MODULE_VERSION_MICRO),$(MODULE_VERSION_EXTRA)',
                             '']
                 ))

def write_makefile_common(folder, dispatchable_obj):
   with open(os.path.join(folder, 'Makefile.common'), 'w') as mfile:
      mfile.write('\n'.join(['# This file automatically generated using Transmute',
                             'PLUGIN_NAME = {}'.format(dispatchable_obj.abbreviation),
                             '',
                             'NONGENERATED_REGISTER_C_FILES = \\',
                             '\tpacket-{}.c'.format(dispatchable_obj.abbreviation),
                             '',
                             'NONGENERATED_C_FILES = \\',
                             '\t$(NONGENERATED_REGISTER_C_FILES)',
                             '',
                             'CLEAN_HEADER_FILES = \\',
                             '\tpacket-{}.h'.format(dispatchable_obj.abbreviation),
                             '',
                             'HEADER_FILES = \\',
                             '\t$(CLEAN_HEADER_FILES)',
                             '',
                             'include ../Makefile.common.inc',
                             '']
                 ))

def write_makefile_am(folder, dispatchable_obj):
   with open(os.path.join(folder, 'Makefile.am'), 'w') as mfile:
      mfile.write('\n'.join(['# This file automatically generated using Transmute',
                             'include $(top_srcdir)/Makefile.am.inc',
                             '',
                             'AM_CPPFLAGS = -I$(top_srcdir)',
                             '',
                             'include Makefile.common',
                             '',
                             'if HAVE_WARNINGS_AS_ERRORS',
                             'AM_CFLAGS = -Werror',
                             'endif',
                             '',
                             'plugindir = @plugindir@',
                             '',
                             'plugin_LTLIBRARIES = {}.la'.format(dispatchable_obj.abbreviation),
                             '',
                             '{}_la_SOURCES = \\'.format(dispatchable_obj.abbreviation),
                             '\tplugin.c \\',
                             '\tmoduleinfo.h \\',
                             '\t$(SRC_FILES)\t\\',
                             '\t$(HEADER_FILES)',
                             '',
                             '{}_la_LDFLAGS = -module -avoid-version'.format(dispatchable_obj.abbreviation),
                             '{}_la_LIBADD = @PLUGIN_LIBS@'.format(dispatchable_obj.abbreviation),
                             '',
                             'LIBS =',
                             '',
                             'plugin.c: $(REGISTER_SRC_FILES) Makefile.common $(top_srcdir)/tools/make-dissector-reg \\',
                             '    $(top_srcdir)/tools/make-dissector-reg.py',
                             '\t@if test -n "$(PYTHON)"; then \\',
                             '\t\techo Making plugin.c with python ; \\',
                             '\t\t$(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \\',
                             '\t\t    plugin $(REGISTER_SRC_FILES) ; \\',
                             '\telse \\',
                             '\t\techo Making plugin.c with shell script ; \\',
                             '\t\t$(top_srcdir)/tools/make-dissector-reg $(srcdir) \\',
                             '\t\t    $(plugin_src) plugin $(REGISTER_SRC_FILES) ; \\',
                             '\tfi',
                             '',
                             '',
                             'CLEANFILES = \\',
                             '\t{} \\'.format(dispatchable_obj.abbreviation),
                             '\t*~',
                             '',
                             'MAINTAINERCLEANFILES = \\',
                             '\tMakefile.in\t\\',
                             '\tplugin.c',
                             '',
                             'EXTRA_DIST = \\',
                             '\tMakefile.common\t\t\\',
                             '\tMakefile.nmake\t\t\\',
                             '\tmoduleinfo.nmake\t\\',
                             '\tplugin.rc.in\t\t\\',
                             '\tCMakeLists.txt',
                             '',
                             'checkapi:',
                             '\t$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \\',
                             '\t\t$(CLEAN_SRC_FILES) $(CLEAN_HEADER_FILES)',
                             '']
                 ))

def write_makefile_nmake(folder, dispatchable_obj):
   with open(os.path.join(folder, 'Makefile.nmake'), 'w') as mfile:
      mfile.write('\n'.join(['# This file automatically generated using Transmute',
                             'include ..\\..\\config.nmake',
                             'include ..\\..\\Makefile.nmake.inc',
                             '',
                             'include moduleinfo.nmake',
                             '',
                             'include Makefile.common',
                             '',
                             'CFLAGS=$(WARNINGS_ARE_ERRORS) $(STANDARD_CFLAGS) \\',
                             '\t/I../.. $(GLIB_CFLAGS) \\',
                             '\t/I$(PCAP_DIR)\include',
                             '',
                             '.c.obj::',
                             '\t$(CC) $(CFLAGS) -Fd.\\ -c $<',
                             '',
                             'LDFLAGS = $(PLUGIN_LDFLAGS)',
                             '',
                             '!IFDEF ENABLE_LIBWIRESHARK',
                             'LINK_PLUGIN_WITH=..\\..\\epan\\libwireshark.lib',
                             'CFLAGS=$(CFLAGS)',
                             '',
                             'OBJECTS = $(C_FILES:.c=.obj) $(CPP_FILES:.cpp=.obj) plugin.obj',
                             '',
                             'RESOURCE=$(PLUGIN_NAME).res',
                             '',
                             'all: $(PLUGIN_NAME).dll',
                             '',
                             '$(PLUGIN_NAME).rc : moduleinfo.nmake',
                             '\tsed -e s/@PLUGIN_NAME@/$(PLUGIN_NAME)/ \\',
                             '\t-e s/@RC_MODULE_VERSION@/$(RC_MODULE_VERSION)/ \\',
                             '\t-e s/@RC_VERSION@/$(RC_VERSION)/ \\',
                             '\t-e s/@MODULE_VERSION@/$(MODULE_VERSION)/ \\',
                             '\t-e s/@PACKAGE@/$(PACKAGE)/ \\',
                             '\t-e s/@VERSION@/$(VERSION)/ \\',
                             '\t-e s/@MSVC_VARIANT@/$(MSVC_VARIANT)/ \\',
                             '\t< plugin.rc.in > $@',
                             '',
                             '$(PLUGIN_NAME).dll $(PLUGIN_NAME).exp $(PLUGIN_NAME).lib : $(OBJECTS) $(LINK_PLUGIN_WITH) $(RESOURCE)',
                             '\tlink -dll /out:$(PLUGIN_NAME).dll $(LDFLAGS) $(OBJECTS) $(LINK_PLUGIN_WITH) \\',
                             '\t$(GLIB_LIBS) $(RESOURCE)',
                             '',
                             '!IFDEF PYTHON',
                             'plugin.c: $(REGISTER_SRC_FILES) moduleinfo.h Makefile.common ../../tools/make-dissector-reg.py',
                             '\t@echo Making plugin.c (using python)',
                             '\t@$(PYTHON) "../../tools/make-dissector-reg.py" . plugin $(REGISTER_SRC_FILES)',
                             '!ELSE',
                             'plugin.c: $(REGISTER_SRC_FILES) moduleinfo.h Makefile.common ../../tools/make-dissector-reg',
                             '\t@echo Making plugin.c (using sh)',
                             '\t@$(SH) ../../tools/make-dissector-reg . plugin $(REGISTER_SRC_FILES)',
                             '!ENDIF',
                             '',
                             '!ENDIF',
                             'clean:',
                             '\trm -f $(OBJECTS) $(RESOURCE) plugin.c *.pdb *.sbr \\',
                             '\t    $(PLUGIN_NAME).dll $(PLUGIN_NAME).dll.manifest $(PLUGIN_NAME).lib \\',
                             '\t    $(PLUGIN_NAME).exp $(PLUGIN_NAME).rc',
                             '',
                             'distclean: clean',
                             '',
                             'maintainer-clean: distclean',
                             '',
                             'checkapi:',
                             '\t$(PERL) ../../tools/checkAPIs.pl -g abort -g termoutput -build \\',
                             '\t\t$(CLEAN_SRC_FILES) $(CLEAN_HEADER_FILES)',
                             '']
                 ))

def write_plugin_rc_in(folder, dispatchable_obj):
   with open(os.path.join(folder, 'plugin.rc.in'), 'w') as mfile:
      mfile.write('\n'.join([r'#include "winver.h"',
                             r'',
                             r'VS_VERSION_INFO VERSIONINFO',
                             r' FILEVERSION @RC_MODULE_VERSION@',
                             r' PRODUCTVERSION @RC_VERSION@',
                             r' FILEFLAGSMASK 0x0L',
                             r'#ifdef _DEBUG',
                             r' FILEFLAGS VS_FF_DEBUG',
                             r'#else',
                             r' FILEFLAGS 0',
                             r'#endif',
                             r' FILEOS VOS_NT_WINDOWS32',
                             r' FILETYPE VFT_DLL',
                             r'BEGIN',
                             r'    BLOCK "StringFileInfo"',
                             r'    BEGIN',
                             r'        BLOCK "040904b0"',
                             r'        BEGIN',
                             r'            VALUE "CompanyName", "Transmute-users\0"',
                             r'            VALUE "FileDescription", "@PACKAGE@ dissector\0"',
                             r'            VALUE "FileVersion", "@MODULE_VERSION@\0"',
                             r'            VALUE "InternalName", "@PACKAGE@ @MODULE_VERSION@\0"',
                              '            VALUE "LegalCopyright", "Copyright \xa9 2014\\0"', #not a rawstring since we need to interpret the \xa9
                             r'            VALUE "OriginalFilename", "@PLUGIN_NAME@.dll\0"',
                             r'            VALUE "ProductName", "Wireshark\0"',
                             r'            VALUE "ProductVersion", "@VERSION@\0"',
                             r'            VALUE "Comments", "Build with @MSVC_VARIANT@\0"',
                             r'        END',
                             r'    END',
                             r'    BLOCK "VarFileInfo"',
                             r'    BEGIN',
                             r'        VALUE "Translation", 0x409, 1200',
                             r'    END',
                             r'END',
                             r'']
                           ))

def write_moduleinfo_h(folder, dispatchable_obj):
   with open(os.path.join(folder, 'moduleinfo.h'), 'w') as mfile:
      mfile.write('\n'.join(['/* Automatically generated using Transmute',
                             '   Included *after* config.h, in order to re-define these macros */',
                             '',
                             '#ifdef PACKAGE',
                             '#undef PACKAGE',
                             '#endif',
                             '',
                             '/* Name of package */',
                             '#define PACKAGE "{name}"'.format(name = abbr2name(dispatchable_obj.abbreviation)),
                             '',
                             '',
                             '#ifdef VERSION',
                             '#undef VERSION',
                             '#endif',
                             '',
                             '/* Version number of package */',
                             '#define VERSION "{major}.{minor}.{micro}"'.format(**dispatchable_obj.version.data),
                             '',
                             '']))

def dispatch_node(dispatchable_obj, namespace):
   if   dispatchable_obj.getTag() == Field.tag():
      if dispatchable_obj.abbreviation in namespace['fields']:
         raise DispatchError("More than one field with name {name}".format(name = dispatchable_obj.abbreviation))
      namespace['fields'][dispatchable_obj.abbreviation] = dispatchable_obj
   elif dispatchable_obj.getTag() == Message.tag():
      if dispatchable_obj.abbreviation in namespace['messages']:
         raise DispatchError("More than one message with name {name}".format(name = dispatchable_obj.abbreviation))
      if dispatchable_obj.abbreviation in namespace['trees']:
         raise DispatchError("More than one tree with name {name}".format(name = dispatchable_obj.abbreviation))
      namespace['messages'][dispatchable_obj.abbreviation] = dispatchable_obj
      namespace['trees'][dispatchable_obj.abbreviation] = dispatchable_obj
      namespace['handles'][dispatchable_obj.abbreviation] = dispatchable_obj
   elif dispatchable_obj.getTag() == Protocol.tag():
      namespace['handles'][dispatchable_obj.abbreviation] = dispatchable_obj
      namespace['trees'][dispatchable_obj.abbreviation] = dispatchable_obj
   elif dispatchable_obj.getTag() == Values.tag():
      if dispatchable_obj.name in (set(namespace['enums'].keys()) | set(namespace['value_strings'].keys()) | set(namespace['true_false_strings'].keys())):
         if len(dispatchable_obj):
            raise DispatchError("More than one enumeration with name {name}".format(name = dispatchable_obj.name))
      else:
         if not len(dispatchable_obj):
            raise DispatchError("Enumeration '{name}' referenced before definition".format(name = dispatchable_obj.name))
         namespace['enums'][dispatchable_obj.name] = _ws_text['enum'].format(name=dispatchable_obj.name, values=',\n'.join([_ws_text['enum_value'].format(indent=_ws_text['indent'], name=v, value=dispatchable_obj.values[v].ival) for v in dispatchable_obj.values]))
         if is_tfs(dispatchable_obj):
            namespace['true_false_strings'][dispatchable_obj.name] = "{indent}{tfs}".format(**{'indent':_ws_text['indent'], 'tfs':_ws_text['true_false_string'].format(name=dispatchable_obj.name, vtrue=tfg_get(dispatchable_obj,1),vfalse=tfs_get(dispatchable_obj,0))})
         else:
            namespace['value_strings'][dispatchable_obj.name] = "{vs}".format(vs = _ws_text['value_string'].format(name=dispatchable_obj.name, indent=_ws_text['indent'], values=',\n'.join([_ws_text['vs_value'].format(name=v, indent=_ws_text['indent']) for v in dispatchable_obj.values.keys()])))
   elif dispatchable_obj.getTag() == Expose.tag():
      if dispatchable_obj.field in namespace['tables']:
         raise DispatchError("More than one <{}> with name '{}'".format(Expose.tag(), dispatchable_obj.field))
      if not dispatchable_obj.parent.hasField(dispatchable_obj.field):
         raise DispatchError("<{}> specifies unavailable field '{}'".format(Expose.tag(), dispatchable_obj.field))
      namespace['tables'][dispatchable_obj.field] = dispatchable_obj
   elif dispatchable_obj.getTag() == Register.tag():
      if dispatchable_obj.table not in namespace['joins']:
         namespace['joins'][dispatchable_obj.table] = list()
      namespace['joins'][dispatchable_obj.table].append(dispatchable_obj)
   if ws_has_section(dispatchable_obj, 'header'):
      namespace['trees'][dispatchable_obj.header.abbreviation] = dispatchable_obj.header
      namespace['headers'][dispatchable_obj.header.abbreviation] = dispatchable_obj.header
   if ws_has_section(dispatchable_obj, 'trailer'):
      namespace['trees'][dispatchable_obj.trailer.abbreviation] = dispatchable_obj.trailer
      namespace['trailers'][dispatchable_obj.trailer.abbreviation] = dispatchable_obj.trailer
   
   for child in dispatchable_obj.children:
      dispatch_node(child, namespace)

def dispatch(dispatchable_obj):
   if args_ns.wireshark and dispatchable_obj.getTag() == Protocol.tag():
      _logger.debug('Beginning dispatch for {} protocol'.format(dispatchable_obj.name))
      _logger.debug('args_ns is {}'.format(args_ns))
      folder = os.path.join(args_ns.path, dispatchable_obj.abbreviation)
      _logger.debug('Wireshark output to {}'.format(folder))
      try:
         force_folder(folder)
      except ValueError as ve:
         raise DispatchError(ve)
      
      namespace = { 'enums'              : OrderedDict(),
                    'value_strings'      : OrderedDict(),
                    'true_false_strings' : OrderedDict(),
                    'fields'             : OrderedDict(),
                    'messages'           : OrderedDict(),
                    'trees'              : OrderedDict(),
                    'tables'             : OrderedDict(),
                    'joins'              : OrderedDict(),
                    'headers'            : OrderedDict(),
                    'trailers'           : OrderedDict(),
                    'handles'            : OrderedDict()
                  }
      
      dispatch_node(dispatchable_obj, namespace)
      
      with open(os.path.join(folder, 'packet-{}.c'.format(dispatchable_obj.abbreviation)), 'w') as cfile:
         with open(os.path.join(folder, 'packet-{}.h'.format(dispatchable_obj.abbreviation)), 'w') as hfile:
            hfile.write(_ws_text['header_comment'].format(**{'filename':hfile.name, 'description':"The header file for the {} protocol".format(dispatchable_obj.name)}))
            hfile.write('#ifndef {include_guard}\n#define {include_guard}\n'.format(include_guard = ws_include_guard(hfile)))
            cfile.write(_ws_text['header_comment'].format(**{'filename':cfile.name, 'description':"The implementation file for the {} protocol".format(dispatchable_obj.name)}))
            
            hfile.write(_ws_text['header_includes'])
            cfile.write(_ws_text['source_includes'].format(name = dispatchable_obj.abbreviation))
            
            cfile.write('static int proto_{name} = -1;\n'.format(name = abbr2name(dispatchable_obj.abbreviation)))
            for m in dispatchable_obj.messages.values():
               cfile.write('static int proto_{name} = -1;\n'.format(name = abbr2name(m.abbreviation)))
            
            cfile.write('/* Header Fields */\n')
            for field in namespace['fields'].values():
               cfile.write('static int hf_{hf} = -1;\n'.format(hf=abbr2name(field.abbreviation)))
            for msg in namespace['messages'].values():
               cfile.write('static int hf_{hf} = -1;\n'.format(hf=abbr2name(msg.abbreviation)))
            for hdr in namespace['headers'].values():
               cfile.write('static int hf_{hf} = -1;\n'.format(hf=abbr2name(hdr.abbreviation)))
            for trlr in namespace['trailers'].values():
               cfile.write('static int hf_{hf} = -1;\n'.format(hf=abbr2name(trlr.abbreviation)))
            cfile.write('\n')
            
            cfile.write('/* Trees */\n')
            for tree in namespace['trees'].values():
               cfile.write('static gint ett_{ett} = -1;\n'.format(ett=abbr2name(tree.abbreviation)))
            cfile.write('\n')
            
            cfile.write('/* Enumerations */ \n')
            for enum in namespace['enums'].values():
               hfile.write(enum)
            cfile.write('\n')
            
            cfile.write('/* Value Strings */\n')
            for vs in namespace['value_strings'].values():
               hfile.write(var_decl(vs))
               cfile.write(vs)
            cfile.write('\n')
            
            cfile.write('/* True/False Strings */\n')
            for tfs in namespace['true_false_strings'].values():
               hfile.write(var_decl(tfs))
               cfile.write(tfs)
            cfile.write('\n')
            
            cfile.write('/* Dissector Handles */\n')
            for handle in namespace['handles'].values():
               cfile.write('static dissector_handle_t handle_{name};\n'.format(name = abbr2name(handle.abbreviation)))
            cfile.write('\n')
            
            hfile.write('#endif /* {include_guard} */\n'.format(include_guard = ws_include_guard(hfile)))
            
            #dissect_...
            cfile.write('/* dissect_ Functions */\n')
            write_dissect_fxn(dispatchable_obj, cfile)
            #proto_register...
            cfile.write('/* proto_register_ Functions */\n')
            write_register_fxn(dispatchable_obj, cfile)
            #proto_reg_handoff...
            cfile.write('/* proto_reg_handoff_ Functions */\n')
            write_handoff_fxn(dispatchable_obj, cfile, namespace['handles'])
      write_cmake_file(folder, dispatchable_obj)
      write_moduleinfo_file(folder, dispatchable_obj)
      write_makefile_common(folder, dispatchable_obj)
      write_makefile_am(folder, dispatchable_obj)
      write_makefile_nmake(folder, dispatchable_obj)
      write_plugin_rc_in(folder, dispatchable_obj)
      write_moduleinfo_h(folder, dispatchable_obj)
      
