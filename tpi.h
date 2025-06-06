#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include <intrin.h>
#include <ntddndis.h>
#include <strsafe.h>
#include <fltkernel.h>
#include <ntstrsafe.h>


BOOL KpdbTravelTPICodeView(PVOID pdbfile);
LONG KpdbGetStructMemberOffset(PVOID pdbfile, PCHAR StructName, PCHAR MemberName);

#pragma pack(push, 1)
typedef struct {
	ULONG version;
	ULONG header_size;
	ULONG type_index_begin;
	ULONG type_index_end;
	ULONG type_record_bytes;
	USHORT hash_stream_index;
	USHORT hash_aux_stream_index;
	ULONG hash_keys_bytes;
	ULONG num_hash_buckets;
	LONG hash_value_buffer_offset;
	ULONG hash_value_buffer_bytes;
	LONG index_offset_buffer_offset;
	ULONG index_offset_buffer_bytes;
	LONG hash_adj_buffer_offset;
	ULONG hash_adj_buffer_bytes;
} TPIStreamHeader;
#pragma pack(pop)

typedef enum {
	V40 = 19950410,
	V41 = 19951122,
	V50 = 19961031,
	V70 = 19990903,
	V80 = 20040203,
} TpiStreamVersion;

/* LEAF_ENUM_e */
enum cv_leaf_type {
	LF_PAD0 = 0xf0,
	LF_PAD1 = 0xf1,
	LF_PAD2 = 0xf2,
	LF_PAD3 = 0xf3,
	LF_MODIFIER = 0x1001,
	LF_POINTER = 0x1002,
	LF_PROCEDURE = 0x1008,
	LF_MFUNCTION = 0x1009,
	LF_ARGLIST = 0x1201,
	LF_FIELDLIST = 0x1203,
	LF_TYPEDEF = 0x1204,
	LF_BITFIELD = 0x1205,
	LF_METHODLIST = 0x1206,
	LF_BCLASS = 0x1400,
	LF_DBCLASS = 0x1401,
	LF_INDEX = 0x1404,
	LF_ENUMERATE = 0x1502,
	LF_ARRAY = 0x1503,
	LF_CLASS = 0x1504,
	LF_STRUCTURE = 0x1505,
	LF_UNION = 0x1506,
	LF_ENUM = 0x1507,
	LF_MEMBER = 0x150d,
	LF_STMEMBER = 0x150e,
	LF_METHOD = 0x150f,
	LF_NESTTYPE = 0x1510,
	LF_ONEMETHOD = 0x1511,
	LF_FUNC_ID = 0x1601,
	LF_MFUNC_ID = 0x1602,
	LF_STRING_ID = 0x1605,
	LF_CHAR = 0x8000,
	LF_SHORT = 0x8001,
	LF_USHORT = 0x8002,
	LF_LONG = 0x8003,
	LF_ULONG = 0x8004,
	LF_QUADWORD = 0x8009,
	LF_UQUADWORD = 0x800a
};


struct codeview_integer {
    BOOL neg;
    ULONGLONG num;
};

struct codeview_subtype {
    struct codeview_subtype* next;
    enum cv_leaf_type kind;

    union {
        struct {
            char* name;
            struct codeview_integer value;
        } lf_enumerate;
        struct { 
            ULONG type_num;
        } lf_index;
        struct { // LF_MEMBER
            USHORT attributes;
            ULONG type;
            struct codeview_integer offset;
            char* name;
        } lf_member;
        struct { // LF_STMEMBER
            USHORT attributes;
            ULONG type;
            char* name;
        } lf_static_member;
        struct { // LF_ONEMETHOD
            USHORT method_attribute; 
            ULONG method_type;
            LONG vtable_base_offset; 
            char* name;
        } lf_onemethod;
        struct { // LF_METHOD
            USHORT count;
            ULONG method_list;
            char* name;
        } lf_method;
        struct { // LF_BCLASS
            USHORT attributes;
            ULONG base_class_type;
            struct codeview_integer offset;
        } lf_bclass;
        struct { // LF_NESTTYPE
            USHORT attributes;
            ULONG type;
            char* name;
        } lf_nesttype;
    };
};

struct codeview_custom_type {
    struct codeview_custom_type* next;
    ULONG _index;
    enum cv_leaf_type kind;
    USHORT original_record_reclen;

    union {
        struct {
            ULONG base_type;
            ULONG attributes;
            
        } lf_pointer;
        struct {
            ULONG base_type;
            USHORT modifier;
        } lf_modifier;
        struct { // LF_FIELDLIST
            ULONGLONG length;
            struct codeview_subtype* subtypes;
            struct codeview_subtype* last_subtype;
        } lf_fieldlist;
        struct { // LF_ENUM
            USHORT count;
            USHORT properties;
            ULONG underlying_type;
            ULONG fieldlist_idx;
            char* name;
            char* unique_name;
        } lf_enum;
        struct { // LF_CLASS, LF_STRUCTURE
            USHORT count;
            USHORT properties;
            ULONG field_list_idx;
            ULONG derived_from_idx;
            ULONG vshape_idx;
            struct codeview_integer structure_length;
            char* name;
            char* unique_name;
        } lf_structure;
        struct {
            ULONG element_type;
            ULONG index_type;
            struct codeview_integer length_in_bytes;
        } lf_array;
        struct {
            ULONG base_type;
            UCHAR length;
            UCHAR position;
        } lf_bitfield;
        struct {
            ULONG return_type;
            UCHAR calling_convention;
            UCHAR attributes;
            USHORT num_parameters;
            ULONG arglist_idx;
        } lf_procedure;
        struct { // LF_ARGLIST
            ULONG num_entries;
            ULONG* args;
        } lf_arglist;
        struct {
            ULONG return_type;
            ULONG containing_class_type;
            ULONG this_type;
            UCHAR calling_convention;
            UCHAR attributes;
            USHORT num_parameters;
            ULONG arglist_idx;
            LONG this_adjustment;
        } lf_mfunction;
        struct {
            ULONG underlying_type_idx;
            char* name;
        } lf_typedef;
        struct {
            const UCHAR* data_ptr;
            ULONG data_size;
        } lf_unhandled;

        struct {
            ULONG parent_scope;
            ULONG function_type;
            char* name;
        } lf_func_id_common;

        struct { // LF_STRING_ID
            ULONG substring_list_idx;
            char* string;
        } lf_string_id;
    };
};


/* Constants for in-built types.  */
#define T_VOID 0x0003
#define T_HRESULT 0x0008
#define T_CHAR 0x0010
#define T_SHORT 0x0011
#define T_LONG 0x0012
#define T_QUAD 0x0013
#define T_UCHAR 0x0020
#define T_USHORT 0x0021
#define T_ULONG 0x0022
#define T_UQUAD 0x0023
#define T_BOOL08 0x0030
#define T_REAL32 0x0040
#define T_REAL64 0x0041
#define T_REAL80 0x0042
#define T_REAL128 0x0043
#define T_RCHAR 0x0070
#define T_WCHAR 0x0071
#define T_INT4 0x0074   // Typically 32-bit int
#define T_UINT4 0x0075  // Typically 32-bit unsigned int
#define T_CHAR16 0x007a // char16_t
#define T_CHAR32 0x007b // char32_t
#define T_CHAR8 0x007c  // char8_t (C++20)


// CV_PROPERTY flags
#define CV_PPROP_PACKED 0x0001
#define CV_PPROP_HASCTORORDTOR 0x0002
#define CV_PPROP_HASOVERLOADEDOPERATOR 0x0004
#define CV_PPROP_ISNESTED 0x0008
#define CV_PPROP_HASNESTEDTYPE 0x0010
#define CV_PPROP_HASOVERLOADEDASSIGN 0x0020
#define CV_PPROP_HASCONVERSIONOPERATOR 0x0040
#define CV_PPROP_FORWARDREF 0x0080
#define CV_PPROP_SCOPED 0x0100
#define CV_PPROP_HASUNIQUENAME 0x0200

typedef struct {
    USHORT reclen;
    USHORT type;
    const UCHAR* data_ptr;
} RawTypeRecord;

typedef struct {
    UCHAR* data;
    ULONG size;
    TPIStreamHeader header;
    BOOL parsed_header;
} TPIStream;

typedef struct {
    struct codeview_custom_type** types;
    int count;
    int capacity;
} TPIContext;

typedef struct {
    int indent_level;
    int current_depth;
    int max_depth;
    BOOL show_details;
    TPIContext* _tpi_ctx;
} PrintContext;


typedef enum {
    TPI_OK = 0,
    TPI_FILE_ERROR,
    TPI_FORMAT_ERROR,
    TPI_PARSE_ERROR,
    TPI_MEMORY_ERROR,
    TPI_ITEM_NOT_FOUND,
    TPI_BUFFER_TOO_SMALL,
    TPI_INVALID_PARAMETER
} TPIResult;


#define TPI_CHECK(expr)                                                        \
  do {                                                                         \
    TPIResult res_macro_internal = (expr);                                     \
    if (res_macro_internal != TPI_OK)                                          \
      return res_macro_internal;                                               \
  } while (0)

#define TPI_CHECK_GOTO(expr, label)                                            \
  do {                                                                         \
    if ((expr) != TPI_OK)                                                      \
      goto label;                                                              \
  } while (0)


