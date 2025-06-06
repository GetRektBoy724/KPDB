#include "tpi.h"
#include "kpdb.h"


TPIResult get_type_name_str_by_index(TPIContext* ctx, ULONG type_index,
	char* output_buffer, ULONGLONG buffer_length);
void get_leaf_type_name_str(USHORT leaf_type, char* output_buffer, ULONGLONG buffer_length);
struct codeview_custom_type* find_type_by_index(TPIContext* context, ULONG index);

BOOL get_friendly_primitive_name(ULONG type_index, char* output_buffer,
	ULONGLONG buffer_length);
void format_member_attributes_str(USHORT field_attributes, char* output_buffer,
	ULONGLONG buffer_length);
void format_method_attributes_str(USHORT method_attributes, char* output_buffer,
	ULONGLONG buffer_length);

TPIResult parse_raw_record_to_cv_type(ULONG type_idx,
	RawTypeRecord raw_record,
	struct codeview_custom_type** out_cv_type_ptr);

void free_codeview_custom_type(struct codeview_custom_type* cv_type);
TPIResult add_type(TPIContext* context, struct codeview_custom_type* cv_type_to_add);


void free_tpi_context(TPIContext* ctx) {
    if (!ctx)
        return;
    if (ctx->types) {
        for (int i = 0; i < ctx->count; i++) {
            free_codeview_custom_type(ctx->types[i]);
            ctx->types[i] = NULL;
        }
        ExFreePool(ctx->types);
        ctx->types = NULL;
    }
    ctx->count = 0;
    ctx->capacity = 0;
}

#define MAX_TYPE_NAME_BUF 512

 TPIResult get_type_name_str_by_index(TPIContext* ctx, ULONG type_index,
    char* output_buffer, ULONGLONG buffer_length) {
    if (!ctx || !output_buffer || buffer_length == 0)
        return TPI_INVALID_PARAMETER;
    output_buffer[0] = '\0';

    if (type_index == 0) {
        RtlStringCchCopyNA(output_buffer, buffer_length, "<no type>", buffer_length - 1);
        output_buffer[buffer_length - 1] = '\0';
        return TPI_OK;
    }
    if (type_index < 0x1000) { // Primitive types
        if (get_friendly_primitive_name(type_index, output_buffer, buffer_length)) {
            // Name is already in output_buffer
        }
        else {
            RtlStringCchPrintfA(output_buffer, buffer_length, "<Primitive Type 0x%x>", type_index);
        }
        output_buffer[buffer_length - 1] = '\0';
        return TPI_OK;
    }

    struct codeview_custom_type* cv_type = find_type_by_index(ctx, type_index);
    if (cv_type) {
        char* name_to_use = NULL;
        char* unique_name_to_use = NULL;

        switch (cv_type->kind) {
        case LF_CLASS:
        case LF_STRUCTURE:
            name_to_use = cv_type->lf_structure.name;
            unique_name_to_use = cv_type->lf_structure.unique_name;
            break;
        case LF_ENUM:
            name_to_use = cv_type->lf_enum.name;
            unique_name_to_use = cv_type->lf_enum.unique_name;
            break;
        case LF_TYPEDEF:
            name_to_use = cv_type->lf_typedef.name;
            break;
        default:
            break;
        }

        if (name_to_use && name_to_use[0] != '\0') {
            RtlStringCchCopyNA(output_buffer, buffer_length, name_to_use, buffer_length - 1);
        }
        else if (unique_name_to_use && unique_name_to_use[0] != '\0') {
            RtlStringCchPrintfA(output_buffer, buffer_length, "<unique: %s>", unique_name_to_use);
        }
        else if (cv_type->kind == LF_MODIFIER && cv_type->lf_modifier.base_type != 0) {
            char modifier_string[64] = "";
            if (cv_type->lf_modifier.modifier & 0x01) {
                RtlStringCchCatNA(modifier_string, sizeof(modifier_string), "const ", sizeof(modifier_string) - RtlStringCchLengthA(modifier_string, STRSAFE_MAX_CCH, NULL) - 1);
            }
            if (cv_type->lf_modifier.modifier & 0x02)
                RtlStringCchCatNA(modifier_string, sizeof(modifier_string), "volatile ", sizeof(modifier_string) - RtlStringCchLengthA(modifier_string, STRSAFE_MAX_CCH, NULL)- 1);

            ULONGLONG modifier_string_length = strlen(modifier_string);
            if (modifier_string_length > 0 && modifier_string[modifier_string_length - 1] == ' ')
                modifier_string[modifier_string_length - 1] = '\0';

            char referent_name_buffer[MAX_TYPE_NAME_BUF / 2];
            TPIResult res = get_type_name_str_by_index(
                ctx, cv_type->lf_modifier.base_type, referent_name_buffer,
                sizeof(referent_name_buffer));
            if (res != TPI_OK && res != TPI_ITEM_NOT_FOUND) return res;

            modifier_string_length = 0;
            RtlStringCchLengthA(modifier_string, STRSAFE_MAX_CCH, &modifier_string_length);
            RtlStringCchPrintfA(output_buffer, buffer_length, "%s%s%s", modifier_string, (modifier_string_length > 0 ? " " : ""), referent_name_buffer);
        }
        else {
            char leaf_name_buffer[64];
            get_leaf_type_name_str(cv_type->kind, leaf_name_buffer, sizeof(leaf_name_buffer));
            RtlStringCchPrintfA(output_buffer, buffer_length, "<Unnamed %s (Index 0x%x)>", leaf_name_buffer, cv_type->_index);
        }
    }
    else {
        RtlStringCchPrintfA(output_buffer, buffer_length, "<Unknown Type 0x%x>", type_index);
        return TPI_ITEM_NOT_FOUND;
    }
    output_buffer[buffer_length - 1] = '\0';
    return TPI_OK;
}



 int advance_ptr(const UCHAR** data_stream_ptr_addr, ULONG* remaining_len,
    ULONG amount_to_advance) {
    if (*remaining_len < amount_to_advance)
        return 0;
    *data_stream_ptr_addr += amount_to_advance;
    *remaining_len -= amount_to_advance;
    return 1;
}

#define MAX_STRING_LEN 2048

const char* extract_string_static_temp(const UCHAR* data,
    ULONG max_data_length) {
    static char buffer[MAX_STRING_LEN];
    ULONGLONG i = 0;
    if (!data || max_data_length == 0) {
        buffer[0] = '\0';
        return buffer;
    }
    while (i < max_data_length && i < (sizeof(buffer) - 1)) {
        if (data[i] == 0)
            break;
        buffer[i] = (char)data[i];
        i++;
    }
    buffer[i] = '\0';
    return buffer;
}



 TPIResult parse_codeview_integer(const UCHAR** data_stream_ptr_addr, ULONG* bytes_consumed_out,
    ULONG available_data, struct codeview_integer* out_val) {
    const UCHAR* data = *data_stream_ptr_addr;
    *bytes_consumed_out = 0;
    out_val->neg = FALSE;
    out_val->num = 0;

    if (available_data < sizeof(USHORT)) {
        DbgPrintEx(0,0,"NumericLeaf: Not enough data to read leaf type (need 2, got %u)\n", available_data);
        return TPI_BUFFER_TOO_SMALL;
    }
    USHORT leaf_type = *(USHORT*)data;

    if (leaf_type < 0x8000) { // It's the value itself if < LF_CHAR (0x8000)
        out_val->num = leaf_type;
        *data_stream_ptr_addr += sizeof(USHORT);
        *bytes_consumed_out = sizeof(USHORT);
        return TPI_OK;
    }

    const UCHAR* value_ptr = data + sizeof(USHORT);
    ULONG required_value_size = 0;

    switch (leaf_type) {
    case LF_CHAR:    required_value_size = sizeof(CHAR); break;
    case LF_SHORT:   required_value_size = sizeof(SHORT); break;
    case LF_USHORT:  required_value_size = sizeof(USHORT); break;
    case LF_LONG:    required_value_size = sizeof(LONG); break;
    case LF_ULONG:   required_value_size = sizeof(ULONG); break;
    case LF_QUADWORD:  required_value_size = sizeof(LONGLONG); break;
    case LF_UQUADWORD: required_value_size = sizeof(ULONGLONG); break;
    default:
        DbgPrintEx(0,0,"Unhandled numeric leaf type 0x%X for codeview_integer\n", leaf_type);
        return TPI_FORMAT_ERROR;
    }

    if (available_data < sizeof(USHORT) + required_value_size) {
        DbgPrintEx(0,0,"NumericLeaf: Not enough data for 0x%X (need %u, got %u)\n", leaf_type, (unsigned int)(sizeof(USHORT) + required_value_size), available_data);
        return TPI_BUFFER_TOO_SMALL;
    }

    switch (leaf_type) {
    case LF_CHAR: { CHAR val = *(CHAR*)value_ptr; if (val < 0) { out_val->neg = TRUE; out_val->num = -val; } else { out_val->num = val; } break; }
    case LF_SHORT: { SHORT val = *(SHORT*)value_ptr; if (val < 0) { out_val->neg = TRUE; out_val->num = -val; } else { out_val->num = val; } break; }
    case LF_USHORT: out_val->num = *(USHORT*)value_ptr; break;
    case LF_LONG: { LONG val = *(LONG*)value_ptr; if (val < 0) { out_val->neg = TRUE; out_val->num = -val; } else { out_val->num = val; } break; }
    case LF_ULONG: out_val->num = *(ULONG*)value_ptr; break;
    case LF_QUADWORD: { LONGLONG val = *(LONGLONG*)value_ptr; if (val < 0) { out_val->neg = TRUE; out_val->num = -val; } else { out_val->num = val; } break; }
    case LF_UQUADWORD: out_val->num = *(ULONGLONG*)value_ptr; break;
    }
    *data_stream_ptr_addr = value_ptr + required_value_size;
    *bytes_consumed_out = sizeof(USHORT) + required_value_size;
    return TPI_OK;
}


 void free_codeview_subtype(struct codeview_subtype* subtype) {
    if (!subtype) return;
    switch (subtype->kind) {
    case LF_ENUMERATE:
        ExFreePool(subtype->lf_enumerate.name);
        break;
    case LF_MEMBER:
        ExFreePool(subtype->lf_member.name);
        break;
    case LF_STMEMBER:
        ExFreePool(subtype->lf_static_member.name);
        break;
    case LF_ONEMETHOD:
        ExFreePool(subtype->lf_onemethod.name);
        break;
    case LF_METHOD:
        ExFreePool(subtype->lf_method.name);
        break;
    case LF_NESTTYPE:
        ExFreePool(subtype->lf_nesttype.name);
        break;
    default:
        break;
    }
    ExFreePool(subtype);
}



 void free_codeview_custom_type(struct codeview_custom_type* cv_type) {
    if (!cv_type) return;

    switch (cv_type->kind) {
    case LF_CLASS:
    case LF_STRUCTURE:
        ExFreePool(cv_type->lf_structure.name);
        ExFreePool(cv_type->lf_structure.unique_name);
        break;
    case LF_ENUM:
        ExFreePool(cv_type->lf_enum.name);
        ExFreePool(cv_type->lf_enum.unique_name);
        break;
    case LF_TYPEDEF:
        ExFreePool(cv_type->lf_typedef.name);
        break;
    case LF_ARGLIST:
        ExFreePool(cv_type->lf_arglist.args);
        break;
    case LF_FIELDLIST: {
        struct codeview_subtype* current_subtype = cv_type->lf_fieldlist.subtypes;
        while (current_subtype) {
            struct codeview_subtype* next_subtype = current_subtype->next;
            free_codeview_subtype(current_subtype);
            current_subtype = next_subtype;
        }
        break;
    }
    case LF_FUNC_ID:
    case LF_MFUNC_ID:
        ExFreePool(cv_type->lf_func_id_common.name);
        break;
    case LF_STRING_ID:
        ExFreePool(cv_type->lf_string_id.string);
        break;
    default:
        break;
    }
    ExFreePool(cv_type);
}



 TPIResult parse_subtype_lf_member_stmember(
    const UCHAR** data_stream_ptr_addr, ULONG* remaining_length_ptr,
    struct codeview_subtype* out_subtype, enum cv_leaf_type actual_kind) {

    if (*remaining_length_ptr < sizeof(USHORT) + sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;

    USHORT attributes = *(USHORT*)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    ULONG type_idx = *(ULONG*)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    struct codeview_integer offset_val = { 0 };
    if (actual_kind == LF_MEMBER) {
        ULONG numeric_bytes_consumed = 0;
        TPIResult pres = parse_codeview_integer(data_stream_ptr_addr, &numeric_bytes_consumed, *remaining_length_ptr, &offset_val);
        if (pres != TPI_OK) return pres;
 
        if (numeric_bytes_consumed > *remaining_length_ptr) return TPI_BUFFER_TOO_SMALL; 
        *remaining_length_ptr -= numeric_bytes_consumed;
    }

    if (*remaining_length_ptr == 0) return TPI_BUFFER_TOO_SMALL; // Name must exist
    const char* name_str_temp = extract_string_static_temp(*data_stream_ptr_addr, *remaining_length_ptr);
    ULONGLONG name_len;
    RtlStringCchLengthA(name_str_temp, MAX_STRING_LEN, &name_len);

    char* name_alloc = (char*)ExAllocatePool(PagedPool, name_len + 1);
    if (!name_alloc) return TPI_MEMORY_ERROR;

    // strcpy(name_alloc, name_str_temp);
    RtlStringCchCopyA(name_alloc, name_len + 1, name_str_temp);

    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, (ULONG)(name_len + 1))) {
        ExFreePool(name_alloc);
        return TPI_BUFFER_TOO_SMALL;
    }

    if (actual_kind == LF_MEMBER) {
        out_subtype->lf_member.attributes = attributes;
        out_subtype->lf_member.type = type_idx;
        out_subtype->lf_member.offset = offset_val;
        out_subtype->lf_member.name = name_alloc;
    }
    else { // LF_STMEMBER
        out_subtype->lf_static_member.attributes = attributes;
        out_subtype->lf_static_member.type = type_idx;
        out_subtype->lf_static_member.name = name_alloc;
    }
    return TPI_OK;
}


 TPIResult parse_subtype_lf_enumerate(
    const UCHAR** data_stream_ptr_addr, ULONG* remaining_length_ptr,
    struct codeview_subtype* out_subtype) {

    if (*remaining_length_ptr < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL; // attributes
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;


    ULONG numeric_bytes_consumed = 0;
    struct codeview_integer enum_val = { 0 };
    TPIResult pres = parse_codeview_integer(data_stream_ptr_addr, &numeric_bytes_consumed, *remaining_length_ptr, &enum_val);
    if (pres != TPI_OK) return pres;
    if (numeric_bytes_consumed > *remaining_length_ptr) return TPI_BUFFER_TOO_SMALL;
    *remaining_length_ptr -= numeric_bytes_consumed;


    if (*remaining_length_ptr == 0) return TPI_BUFFER_TOO_SMALL;
    const char* name_str_temp = extract_string_static_temp(*data_stream_ptr_addr, *remaining_length_ptr);

    // ULONGLONG name_len = strlen(name_str_temp);
    ULONGLONG name_len = 0; RtlStringCchLengthA(name_str_temp, MAX_STRING_LEN, &name_len);
    
    out_subtype->lf_enumerate.name = (char*)ExAllocatePool(PagedPool, name_len + 1); // malloc(name_len + 1);
    if (!out_subtype->lf_enumerate.name) return TPI_MEMORY_ERROR;
    
    // strcpy(out_subtype->lf_enumerate.name, name_str_temp);
    RtlStringCchCopyA(out_subtype->lf_enumerate.name, name_len + 1, name_str_temp);

    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, (ULONG)(name_len + 1))) {
        ExFreePool(out_subtype->lf_enumerate.name);
        out_subtype->lf_enumerate.name = NULL;
        return TPI_BUFFER_TOO_SMALL;
    }
    out_subtype->lf_enumerate.value = enum_val;
    return TPI_OK;
}

 TPIResult parse_subtype_lf_onemethod(
    const UCHAR** data_stream_ptr_addr, ULONG* remaining_length_ptr,
    struct codeview_subtype* out_subtype) {

    if (*remaining_length_ptr < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL;
    USHORT attributes = *(PUSHORT)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    if (*remaining_length_ptr < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    ULONG type_idx = *(PULONG)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    LONG vbaseoff = 0;
    // LF_ONEMETHOD has an optional 4-byte 'vbaseoff' if method is introducing virtual
    // CV_methodprop_e: intro -> 0x04, static_intro -> 0x05, pure_intro -> 0x06
    UCHAR method_prop = (attributes >> 2) & 0x07;
    if (method_prop == 4 || method_prop == 5 || method_prop == 6) {
        if (*remaining_length_ptr < sizeof(LONG)) return TPI_BUFFER_TOO_SMALL;
        vbaseoff = *(PLONG)(*data_stream_ptr_addr);
        if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(LONG))) return TPI_BUFFER_TOO_SMALL;
    }

    if (*remaining_length_ptr == 0) return TPI_BUFFER_TOO_SMALL;
    const char* name_str_temp = extract_string_static_temp(*data_stream_ptr_addr, *remaining_length_ptr);

    ULONGLONG name_len = 0;
    RtlStringCchLengthA(name_str_temp, MAX_STRING_LEN, &name_len);
    out_subtype->lf_onemethod.name = (PCHAR)ExAllocatePool(PagedPool, (SIZE_T)(name_len + 1)); 

    if (!out_subtype->lf_onemethod.name) return TPI_MEMORY_ERROR;
    RtlStringCchCopyA(out_subtype->lf_onemethod.name, (SIZE_T)(name_len + 1), name_str_temp);

    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, (ULONG)(name_len + 1))) {
        ExFreePool(out_subtype->lf_onemethod.name);
        out_subtype->lf_onemethod.name = NULL;
        return TPI_BUFFER_TOO_SMALL;
    }

    out_subtype->lf_onemethod.method_attribute = attributes;
    out_subtype->lf_onemethod.method_type = type_idx;
    out_subtype->lf_onemethod.vtable_base_offset = vbaseoff;
    return TPI_OK;
}

 TPIResult parse_subtype_lf_method(
    const UCHAR** data_stream_ptr_addr, ULONG* remaining_length_ptr,
    struct codeview_subtype* out_subtype) {

    if (*remaining_length_ptr < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL;
    USHORT count = *(PUSHORT)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    if (*remaining_length_ptr < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    ULONG mlist_type_idx = *(PULONG)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    if (*remaining_length_ptr == 0) return TPI_BUFFER_TOO_SMALL;
    const char* name_str_temp = extract_string_static_temp(*data_stream_ptr_addr, *remaining_length_ptr);
    ULONGLONG name_len = 0; // strlen(name_str_temp);
    RtlStringCchLengthA(name_str_temp, MAX_STRING_LEN, &name_len);


    out_subtype->lf_method.name = (PCHAR)ExAllocatePool(PagedPool, (SIZE_T)(name_len + 1)); // malloc(name_len + 1);
    if (!out_subtype->lf_method.name) return TPI_MEMORY_ERROR;
    // strcpy(out_subtype->lf_method.name, name_str_temp);
    RtlStringCchCopyA(out_subtype->lf_method.name, (SIZE_T)(name_len + 1), name_str_temp);

    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, (ULONG)(name_len + 1))) {
        ExFreePool(out_subtype->lf_method.name);
        out_subtype->lf_method.name = NULL;
        return TPI_BUFFER_TOO_SMALL;
    }
    out_subtype->lf_method.count = count;
    out_subtype->lf_method.method_list = mlist_type_idx;
    return TPI_OK;
}

 TPIResult parse_subtype_lf_nesttype(
    const UCHAR** data_stream_ptr_addr, ULONG* remaining_length_ptr,
    struct codeview_subtype* out_subtype) {

    // LF_NESTTYPE: attributes (uint16_t), type_index (uint32_t), name (string)
    if (*remaining_length_ptr < sizeof(USHORT) + sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;

    USHORT attributes = *(USHORT*)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    ULONG type_idx = *(ULONG*)(*data_stream_ptr_addr);
    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    if (*remaining_length_ptr == 0) return TPI_BUFFER_TOO_SMALL;
    const char* name_str_temp = extract_string_static_temp(*data_stream_ptr_addr, *remaining_length_ptr);
    ULONGLONG name_len = 0; // strlen(name_str_temp);
    RtlStringCchLengthA(name_str_temp, MAX_STRING_LEN, &name_len);

    char* name_alloc = (PCHAR)ExAllocatePool(PagedPool, (SIZE_T)(name_len + 1)); // (PCHAR)malloc(name_len + 1);
    if (!name_alloc) return TPI_MEMORY_ERROR;
    
    // strcpy(name_alloc, name_str_temp);
    RtlStringCchCopyA(name_alloc, (SIZE_T)(name_len + 1), name_str_temp);

    if (!advance_ptr(data_stream_ptr_addr, remaining_length_ptr, (ULONG)(name_len + 1))) {
        ExFreePool(name_alloc);
        name_alloc = NULL;
        return TPI_BUFFER_TOO_SMALL;
    }

    out_subtype->lf_nesttype.attributes = attributes;
    out_subtype->lf_nesttype.type = type_idx;
    out_subtype->lf_nesttype.name = name_alloc;

    return TPI_OK;
}

 TPIResult parse_cv_lf_fieldlist(const UCHAR* data, ULONG data_length,
    struct codeview_custom_type* out_cv_type) {
    out_cv_type->lf_fieldlist.subtypes = NULL;
    out_cv_type->lf_fieldlist.last_subtype = NULL;
    out_cv_type->lf_fieldlist.length = 0;

    const UCHAR* current_ptr = data;
    ULONG remaining_len = data_length;

    while (remaining_len > 0) {

        if (remaining_len < sizeof(USHORT)) break; // Not enough for a kind
        USHORT subtype_kind_val = *(PUSHORT)current_ptr;
        enum cv_leaf_type subtype_kind = (enum cv_leaf_type)subtype_kind_val;

        // Data for the subtype starts after the kind field
        const UCHAR* sub_record_data_start = current_ptr + sizeof(USHORT);
        // Available length for the current subtype's data
        ULONG sub_record_available_len = remaining_len - sizeof(USHORT);


        if (subtype_kind >= LF_PAD0 && subtype_kind <= LF_PAD3) {
            UCHAR pad_bytes = subtype_kind_val & 0x0F;
            ULONG advance_amount = sizeof(USHORT) + pad_bytes; // Total to advance for kind + padding bytes
            if (!advance_ptr(&current_ptr, &remaining_len, advance_amount)) return TPI_BUFFER_TOO_SMALL;
            continue;
        }

        struct codeview_subtype* new_subtype = (struct codeview_subtype*)ExAllocatePoolWithTag(PagedPool, sizeof(struct codeview_subtype), 'sVCT');
        if (new_subtype) {
            RtlZeroMemory(new_subtype, sizeof(struct codeview_subtype));
        }
        else {
            return TPI_MEMORY_ERROR;
        }

        new_subtype->kind = subtype_kind;
        new_subtype->next = NULL;

        const UCHAR* data_stream_for_subtype_parser = sub_record_data_start;
        ULONG remaining_for_subtype_parser = sub_record_available_len;
        TPIResult pres = TPI_OK;

        switch (subtype_kind) {
        case LF_MEMBER:
        case LF_STMEMBER:
            pres = parse_subtype_lf_member_stmember(&data_stream_for_subtype_parser, &remaining_for_subtype_parser, new_subtype, subtype_kind);
            break;
        case LF_ENUMERATE:
            pres = parse_subtype_lf_enumerate(&data_stream_for_subtype_parser, &remaining_for_subtype_parser, new_subtype);
            break;
        case LF_ONEMETHOD:
            pres = parse_subtype_lf_onemethod(&data_stream_for_subtype_parser, &remaining_for_subtype_parser, new_subtype);
            break;
        case LF_METHOD:
            pres = parse_subtype_lf_method(&data_stream_for_subtype_parser, &remaining_for_subtype_parser, new_subtype);
            break;
        case LF_NESTTYPE:
            pres = parse_subtype_lf_nesttype(&data_stream_for_subtype_parser, &remaining_for_subtype_parser, new_subtype);
            break;
        case LF_INDEX:
            if (remaining_for_subtype_parser < sizeof(ULONG)) {
                pres = TPI_BUFFER_TOO_SMALL;
            }
            else {
                new_subtype->lf_index.type_num = *(ULONG*)data_stream_for_subtype_parser;
                data_stream_for_subtype_parser += sizeof(ULONG);
                pres = TPI_OK;
            }
            break;
        default:
            // fprintf(stderr, "Unknown or unhandled subtype 0x%04X in fieldlist 0x%X (type index %u).\n", subtype_kind_val, out_cv_type->num, out_cv_type->num);
            free_codeview_subtype(new_subtype);
            return TPI_OK;
        }

        if (pres != TPI_OK) {
            free_codeview_subtype(new_subtype);
            return pres;
        }

        // Link the new subtype
        if (out_cv_type->lf_fieldlist.last_subtype) {
            out_cv_type->lf_fieldlist.last_subtype->next = new_subtype;
        }
        else {
            out_cv_type->lf_fieldlist.subtypes = new_subtype;
        }
        out_cv_type->lf_fieldlist.last_subtype = new_subtype;
        out_cv_type->lf_fieldlist.length++;

        // Calculate how many bytes of data were consumed by the subtype's parser
        ULONG bytes_consumed_by_subtype_data = (ULONG)(data_stream_for_subtype_parser - sub_record_data_start);
        // Total bytes for this field list entry = kind (2 bytes) + data consumed
        ULONG total_bytes_for_this_subtype_entry = sizeof(USHORT) + bytes_consumed_by_subtype_data;

        if (!advance_ptr(&current_ptr, &remaining_len, total_bytes_for_this_subtype_entry)) {
            return TPI_FORMAT_ERROR;
        }

        // Align current_ptr to the next 4-byte boundary for the start of the next subtype
        UINT_PTR current_offset_in_original_fieldlist_data = (UINT_PTR)(current_ptr - data);
        if (current_offset_in_original_fieldlist_data % 4 != 0) {
            ULONG padding = 4 - (current_offset_in_original_fieldlist_data % 4);
            if (!advance_ptr(&current_ptr, &remaining_len, padding)) {
                if (remaining_len != 0) {
                    return TPI_BUFFER_TOO_SMALL;
                }
            }
        }
    }
    return TPI_OK;
}


 TPIResult parse_cv_lf_array(const UCHAR* data, ULONG data_length,
    struct codeview_custom_type* out_cv_type) {
    const UCHAR* current_ptr = data;
    ULONG remaining_len = data_length;
    TPIResult pres;

    memset(&out_cv_type->lf_array, 0, sizeof(out_cv_type->lf_array));

    // Parse element_type (ULONG)
    if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    out_cv_type->lf_array.element_type = *(ULONG*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) {
        return TPI_BUFFER_TOO_SMALL;
    }

    // Parse index_type (ULONG)
    if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    out_cv_type->lf_array.index_type = *(ULONG*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) {
        return TPI_BUFFER_TOO_SMALL;
    }

    // Parse length_in_bytes (numeric leaf)
    ULONG numeric_bytes_consumed = 0;
    pres = parse_codeview_integer(&current_ptr, &numeric_bytes_consumed, remaining_len, &out_cv_type->lf_array.length_in_bytes);
    if (pres != TPI_OK) return pres;

    if (numeric_bytes_consumed > remaining_len) {
        return TPI_BUFFER_TOO_SMALL;
    }
    remaining_len -= numeric_bytes_consumed;

    if (remaining_len > 0) {

        const CHAR* name_temp = extract_string_static_temp(current_ptr, remaining_len);
        
        // ULONGLONG name_len_content = strlen(name_temp);
        ULONGLONG name_len_content = 0;
        RtlStringCchLengthA(name_temp, MAX_STRING_LEN, &name_len_content);

        ULONG bytes_consumed_for_name_field = 0;
        if (name_len_content < remaining_len) {
            bytes_consumed_for_name_field = (ULONG)name_len_content + 1;
        }
        else {
            bytes_consumed_for_name_field = remaining_len;
        }

        if (bytes_consumed_for_name_field > 0) {
            if (!advance_ptr(&current_ptr, &remaining_len, bytes_consumed_for_name_field)) {
                if (remaining_len != 0) return TPI_BUFFER_TOO_SMALL;
            }
        }
    }
    return TPI_OK;
}

 TPIResult parse_cv_lf_class_structure_enum(const UCHAR* data, ULONG data_length,
    struct codeview_custom_type* out_cv_type, USHORT leaf_type) {
    const UCHAR* current_ptr = data;
    ULONG remaining_len = data_length;
    TPIResult pres;

    // Common: count (number of fields/enumerators)
    if (remaining_len < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL;
    USHORT count = *(USHORT*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    // Common: property
    if (remaining_len < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL;
    USHORT property = *(USHORT*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(USHORT))) return TPI_BUFFER_TOO_SMALL;

    ULONG field_list_idx = 0;
    ULONG underlying_type_idx = 0; // For enum
    ULONG derived_list_idx = 0;    // For class/struct
    ULONG vshape_idx = 0;          // For class/struct
    struct codeview_integer struct_size = { 0 }; // For class/struct

    if (leaf_type == LF_ENUM) {
        out_cv_type->lf_enum.count = count;
        out_cv_type->lf_enum.properties = property;

        if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
        underlying_type_idx = *(ULONG*)current_ptr;
        if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;
        out_cv_type->lf_enum.underlying_type = underlying_type_idx;

        if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
        field_list_idx = *(ULONG*)current_ptr;
        if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;
        out_cv_type->lf_enum.fieldlist_idx = field_list_idx;

    }
    else { // LF_CLASS or LF_STRUCTURE
        out_cv_type->lf_structure.count = count;
        out_cv_type->lf_structure.properties = property;

        if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
        field_list_idx = *(ULONG*)current_ptr;
        if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;
        out_cv_type->lf_structure.field_list_idx = field_list_idx;

        if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
        derived_list_idx = *(ULONG*)current_ptr;
        if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;
        out_cv_type->lf_structure.derived_from_idx = derived_list_idx;

        if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
        vshape_idx = *(ULONG*)current_ptr;
        if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;
        out_cv_type->lf_structure.vshape_idx = vshape_idx;

        if (remaining_len > 0) { // Size is numeric (can be 0 bytes if value is small)
            ULONG numeric_bytes_consumed = 0;
            pres = parse_codeview_integer(&current_ptr, &numeric_bytes_consumed, remaining_len, &struct_size);
            if (pres != TPI_OK) return pres;

            if (numeric_bytes_consumed > remaining_len) return TPI_BUFFER_TOO_SMALL;
            remaining_len -= numeric_bytes_consumed;
            out_cv_type->lf_structure.structure_length = struct_size;
        }
        else {
            out_cv_type->lf_structure.structure_length.num = 0;
            out_cv_type->lf_structure.structure_length.neg = FALSE;
        }
    }

    // Name
    if (remaining_len > 0) {
        const char* name_temp = extract_string_static_temp(current_ptr, remaining_len);
        if (name_temp && name_temp[0]) {
            // ULONGLONG len = strlen(name_temp) + 1;
            ULONGLONG name_str_len = 0;
            RtlStringCchLengthA(name_temp, MAX_STRING_LEN, &name_str_len);
            SIZE_T alloc_size = name_str_len + 1; // +1 for null terminator

            char* name_alloc = (PCHAR)ExAllocatePoolWithTag(PagedPool, alloc_size, 'nESC');
            if (name_alloc) {
                RtlZeroMemory(name_alloc, alloc_size);
            }
            else {
                return TPI_MEMORY_ERROR;
            }

            RtlStringCchCopyA(name_alloc, alloc_size, name_temp);

            if (leaf_type == LF_ENUM) out_cv_type->lf_enum.name = name_alloc;
            else out_cv_type->lf_structure.name = name_alloc;

            // Advance by the actual length of the string on stream (including its null terminator)
            // The PDB strings are null terminated on the stream.
            if (!advance_ptr(&current_ptr, &remaining_len, (ULONG)name_str_len + 1)) {
                if (leaf_type == LF_ENUM) { ExFreePoolWithTag(out_cv_type->lf_enum.name, 'nESC'); out_cv_type->lf_enum.name = NULL; }
                else { ExFreePoolWithTag(out_cv_type->lf_structure.name, 'nESC'); out_cv_type->lf_structure.name = NULL; }
                return TPI_BUFFER_TOO_SMALL;
            }
        }
        else if (remaining_len > 0 && *current_ptr == '\0') {
            if (!advance_ptr(&current_ptr, &remaining_len, 1)) return TPI_BUFFER_TOO_SMALL;
        }
    }


    // Unique Name (if CV_PPROP_HASUNIQUENAME is set)
    if ((property & CV_PPROP_HASUNIQUENAME) && remaining_len > 0) {
        const char* uname_temp = extract_string_static_temp(current_ptr, remaining_len);
        if (uname_temp && uname_temp[0]) {
            // ULONGLONG len = strlen(uname_temp) + 1;
            ULONGLONG uname_str_len = 0;
            RtlStringCchLengthA(uname_temp, MAX_STRING_LEN, &uname_str_len);
            SIZE_T u_alloc_size = uname_str_len + 1;

            char* uname_alloc = (PCHAR)ExAllocatePoolWithTag(PagedPool, u_alloc_size, 'uESC');
            if (uname_alloc) {
                RtlZeroMemory(uname_alloc, u_alloc_size);
            }
            else {
                if (uname_alloc) ExFreePoolWithTag(uname_alloc, 'nESC');
                return TPI_MEMORY_ERROR;
            }
            RtlStringCchCopyA(uname_alloc, u_alloc_size, uname_temp);

            if (leaf_type == LF_ENUM) out_cv_type->lf_enum.unique_name = uname_alloc;
            else out_cv_type->lf_structure.unique_name = uname_alloc;

            if (!advance_ptr(&current_ptr, &remaining_len, (ULONG)uname_str_len + 1)) {

                if (leaf_type == LF_ENUM) {
                    if(out_cv_type->lf_enum.name) ExFreePoolWithTag(out_cv_type->lf_enum.name, 'nESC'); out_cv_type->lf_enum.name = NULL;
                    if(out_cv_type->lf_enum.unique_name) ExFreePoolWithTag(out_cv_type->lf_enum.unique_name, 'uESC'); out_cv_type->lf_enum.unique_name = NULL;
                } else {
                    if(out_cv_type->lf_structure.name) ExFreePoolWithTag(out_cv_type->lf_structure.name, 'nESC'); out_cv_type->lf_structure.name = NULL;
                    if(out_cv_type->lf_structure.unique_name) ExFreePoolWithTag(out_cv_type->lf_structure.unique_name, 'uESC'); out_cv_type->lf_structure.unique_name = NULL;
                }
                return TPI_BUFFER_TOO_SMALL;
            }
        }
        else if (remaining_len > 0 && *current_ptr == '\0') {
            if (!advance_ptr(&current_ptr, &remaining_len, 1)) return TPI_BUFFER_TOO_SMALL;
        }
    }
    return TPI_OK;
}

 TPIResult parse_cv_lf_modifier(const UCHAR* data, ULONG data_length,
    struct codeview_custom_type* out_cv_type) {
    const UCHAR* current_ptr = data;
    ULONG remaining_len = data_length;

    if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    out_cv_type->lf_modifier.base_type = *(ULONG*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    if (remaining_len < sizeof(USHORT)) return TPI_BUFFER_TOO_SMALL;
    out_cv_type->lf_modifier.modifier = *(USHORT*)current_ptr;
    return TPI_OK;
}


 TPIResult parse_cv_lf_typedef(const UCHAR* data, ULONG data_length,
    struct codeview_custom_type* out_cv_type) {
    const UCHAR* current_ptr = data;
    ULONG remaining_len = data_length;

    if (remaining_len < sizeof(ULONG)) return TPI_BUFFER_TOO_SMALL;
    out_cv_type->lf_typedef.underlying_type_idx = *(ULONG*)current_ptr;
    if (!advance_ptr(&current_ptr, &remaining_len, sizeof(ULONG))) return TPI_BUFFER_TOO_SMALL;

    if (remaining_len > 0) {
        const char* name_temp = extract_string_static_temp(current_ptr, remaining_len);
        if (name_temp && name_temp[0]) {
            // ULONGLONG len = strlen(name_temp) + 1;
            ULONGLONG name_str_len = 0;
            RtlStringCchLengthA(name_temp, MAX_STRING_LEN, &name_str_len);
            SIZE_T alloc_size = name_str_len + 1;

            out_cv_type->lf_typedef.name = (char*)ExAllocatePoolWithTag(PagedPool, alloc_size, 'nFDT');
            if (out_cv_type->lf_typedef.name) {
                RtlZeroMemory(out_cv_type->lf_typedef.name, alloc_size);
            }
            else {
                return TPI_MEMORY_ERROR;
            }
            RtlStringCchCopyA(out_cv_type->lf_typedef.name, alloc_size, name_temp);
        }
    }
    else {
        out_cv_type->lf_typedef.name = NULL;
    }
    return TPI_OK;
}

 TPIResult parse_raw_record_to_cv_type(ULONG type_idx,
    RawTypeRecord raw_record,
    struct codeview_custom_type** out_cv_type_ptr) {
    *out_cv_type_ptr = NULL;
    
    struct codeview_custom_type* cv_type = (struct codeview_custom_type*)ExAllocatePoolWithTag(PagedPool, sizeof(struct codeview_custom_type), 'pVCT');
    if (cv_type) {
        RtlZeroMemory(cv_type, sizeof(struct codeview_custom_type));
    }
    else {
        return TPI_MEMORY_ERROR;
    }

    if (!cv_type) return TPI_MEMORY_ERROR;

    cv_type->_index = type_idx;
    cv_type->kind = (enum cv_leaf_type)raw_record.type;
    cv_type->original_record_reclen = raw_record.reclen + sizeof(USHORT);

    TPIResult res = TPI_OK;
    const UCHAR* record_content_ptr = raw_record.data_ptr;
    ULONG record_content_len = raw_record.reclen;


    switch (cv_type->kind) {
    case LF_CLASS:
    case LF_STRUCTURE:
    case LF_ENUM:
        res = parse_cv_lf_class_structure_enum(record_content_ptr, record_content_len, cv_type, cv_type->kind);
        break;
    case LF_MODIFIER:
        res = parse_cv_lf_modifier(record_content_ptr, record_content_len, cv_type);
        break;
    case LF_FIELDLIST:
        res = parse_cv_lf_fieldlist(record_content_ptr, record_content_len, cv_type);
        break;
    case LF_TYPEDEF:
        res = parse_cv_lf_typedef(record_content_ptr, record_content_len, cv_type);
        break;
    case LF_ARRAY:
        res = parse_cv_lf_array(record_content_ptr, record_content_len, cv_type);
        break;
    default:
        break;
    }

    if (res != TPI_OK) {
        free_codeview_custom_type(cv_type);
        return res;
    }

    *out_cv_type_ptr = cv_type;
    return TPI_OK;
}

 TPIResult add_type(TPIContext* table, struct codeview_custom_type* cv_type_to_add) {
    if (!table || !cv_type_to_add)
        return TPI_INVALID_PARAMETER;
    if (table->count >= table->capacity) {
        ULONG new_capacity = table->capacity ? table->capacity * 2 : 256;


        /*struct codeview_custom_type** new_types =
            (struct codeview_custom_type**)realloc(table->types, new_capacity * sizeof(struct codeview_custom_type*));*/
        
        
        struct codeview_custom_type** new_types;
        PVOID existing_types_ptr = table->types;
        SIZE_T new_allocation_size_bytes = new_capacity * sizeof(struct codeview_custom_type*);
        new_types = (struct codeview_custom_type**)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            new_allocation_size_bytes,
            'CVTp'
        );

        if (new_types != NULL) {
            if (existing_types_ptr != NULL) {
                SIZE_T old_data_size_bytes = table->count * sizeof(struct codeview_custom_type*);
                SIZE_T bytes_to_copy = (old_data_size_bytes < new_allocation_size_bytes) ? old_data_size_bytes : new_allocation_size_bytes;

                if (bytes_to_copy > 0) {
                    RtlCopyMemory(new_types, existing_types_ptr, bytes_to_copy);
                }
                ExFreePool(existing_types_ptr);
            }
        }

        if (!new_types) {
            DbgPrintEx(0,0,"realloc failed in add_type");
            return TPI_MEMORY_ERROR;
        }
        table->types = new_types;
        table->capacity = new_capacity;
    }
    table->types[table->count++] = cv_type_to_add;
    return TPI_OK;
}

struct codeview_custom_type* find_type_by_index(TPIContext* ctx, ULONG index) {
    if (!ctx)
        return NULL;
    for (int i = 0; i < ctx->count; i++) {
        if (ctx->types[i] && ctx->types[i]->_index == index) {
            return ctx->types[i];
        }
    }
    return NULL;
}

 void get_leaf_type_name_str(USHORT leaf_type_val, char* output_buffer, ULONGLONG buffer_length) {
    enum cv_leaf_type leaf_type = (enum cv_leaf_type)leaf_type_val;
    const char* name_str = NULL;
    switch (leaf_type) {
    case LF_TYPEDEF: name_str = "LF_TYPEDEF"; break;
    case LF_MODIFIER: name_str = "LF_MODIFIER"; break;
    case LF_ARGLIST: name_str = "LF_ARGLIST"; break;
    case LF_FIELDLIST: name_str = "LF_FIELDLIST"; break;
    case LF_ARRAY: name_str = "LF_ARRAY"; break;
    case LF_CLASS: name_str = "LF_CLASS"; break;
    case LF_STRUCTURE: name_str = "LF_STRUCTURE"; break;
    case LF_ENUM: name_str = "LF_ENUM"; break;
    case LF_MEMBER: name_str = "LF_MEMBER"; break;
    case LF_STMEMBER: name_str = "LF_STMEMBER"; break;
    case LF_ENUMERATE: name_str = "LF_ENUMERATE"; break;
    case LF_ONEMETHOD: name_str = "LF_ONEMETHOD"; break;
    case LF_METHOD: name_str = "LF_METHOD"; break;
    case LF_BCLASS: name_str = "LF_BCLASS"; break;
    case LF_POINTER: name_str = "LF_POINTER"; break;
    case LF_PROCEDURE: name_str = "LF_PROCEDURE"; break;
    case LF_MFUNCTION: name_str = "LF_MFUNCTION"; break;
    case LF_BITFIELD: name_str = "LF_BITFIELD"; break;
    case LF_METHODLIST: name_str = "LF_METHODLIST"; break;
    case LF_INDEX: name_str = "LF_INDEX"; break;
    case LF_NESTTYPE: name_str = "LF_NESTTYPE"; break;
    case LF_FUNC_ID: name_str = "LF_FUNC_ID"; break;
    case LF_MFUNC_ID: name_str = "LF_MFUNC_ID"; break;
    case LF_STRING_ID: name_str = "LF_STRING_ID"; break;
    default:
        // snprintf(output_buffer, buffer_length, "LF_UNKNOWN(0x%04X)", leaf_type_val);
        RtlStringCchPrintfA(output_buffer, buffer_length, "LF_UNKNOWN(0x%04X)", leaf_type_val);
        return;
    }
    strncpy(output_buffer, name_str, buffer_length - 1);
    output_buffer[buffer_length - 1] = '\0';
}



 BOOL get_friendly_primitive_name(ULONG type_index, char* output_buffer,
    ULONGLONG buffer_length) {
    const char* name = NULL;
    switch (type_index) {
    case T_VOID: name = "void"; break;
    case T_CHAR: name = "char"; break;
    case T_UCHAR: name = "unsigned char"; break;
    case T_WCHAR: name = "wchar_t"; break;
    case T_RCHAR: name = "char"; break;
    case T_CHAR8: name = "char8_t"; break;
    case T_CHAR16: name = "char16_t"; break;
    case T_CHAR32: name = "char32_t"; break;
    case T_SHORT: name = "short"; break;
    case T_USHORT: name = "unsigned short"; break;
    case T_INT4: name = "int"; break;
    case T_UINT4: name = "unsigned int"; break;
    case T_LONG: name = "long"; break;
    case T_ULONG: name = "unsigned long"; break;
    case T_QUAD: name = "__int64"; break;
    case T_UQUAD: name = "unsigned __int64"; break;
    case T_BOOL08: name = "bool"; break;
    case T_REAL32: name = "float"; break;
    case T_REAL64: name = "double"; break;
    case T_REAL80: name = "long double"; break;
    case T_HRESULT: name = "HRESULT"; break;
    default:
        return FALSE;
    }


    // strncpy(output_buffer, name, buffer_length - 1);
    RtlStringCchCopyA(output_buffer, buffer_length, name);
    output_buffer[buffer_length - 1] = '\0';
    return TRUE;
}


 void format_member_attributes_str(USHORT field_attributes, char* output_buffer,
    ULONGLONG buffer_length) {
    output_buffer[0] = '\0';
    // CV_access_e: 0=none, 1=private, 2=protected, 3=public
    UCHAR access = field_attributes & 0x3;
    const char* access_str = NULL;
    if (access == 1) access_str = "private";
    else if (access == 2) access_str = "protected";
    else if (access == 3) access_str = "public";

    if (access_str) {
        // strncpy(output_buffer, access_str, buffer_length - 1);
        RtlStringCchCopyA(output_buffer, buffer_length, access_str);
        output_buffer[buffer_length - 1] = '\0';
    }
}

 void format_method_attributes_str(USHORT method_attributes, char* output_buffer,
    ULONGLONG buffer_length) {
    output_buffer[0] = '\0';
    UCHAR access = method_attributes & 0x3; // CV_access_e
    const char* access_str = NULL;
    if (access == 1) access_str = "private";
    else if (access == 2) access_str = "protected";
    else if (access == 3) access_str = "public";

    if (access_str) {
        // strncpy(output_buffer, access_str, buffer_length - 1);
        RtlStringCchCopyA(output_buffer, buffer_length, access_str);
        output_buffer[buffer_length - 1] = '\0';
    }

    // CV_methodprop_e: bits 2-4
    // 0=vanilla, 1=virtual, 2=static, 3=friend, 4=intro virtual, 5=pure virtual, 6=pure intro virtual
    UCHAR method_prop = (method_attributes >> 2) & 0x7;
    const char* prop_str = NULL;
    switch (method_prop) {
    case 0: /* vanilla */ break;
    case 1: prop_str = "virtual"; break;
    case 2: prop_str = "static"; break;
    case 3: prop_str = "friend"; break;
    case 4: prop_str = "virtual"; break;
    case 5: prop_str = "pure virtual"; break;
    case 6: prop_str = "pure virtual"; break;
    }

    if (prop_str) {
        if (output_buffer[0] != '\0') {
            RtlStringCchCatA(output_buffer, buffer_length, " ");
        }
        else {
            RtlStringCchCatA(output_buffer, buffer_length, prop_str);
        }
    }
}


 TPIResult check_tpi_header(TPIStream* tpi_stream_ptr) {
    if (!tpi_stream_ptr || !tpi_stream_ptr->data ||
        tpi_stream_ptr->size < sizeof(TPIStreamHeader)) {
        return TPI_FORMAT_ERROR;
    }
    memcpy(&tpi_stream_ptr->header, tpi_stream_ptr->data, sizeof(TPIStreamHeader));
    if (tpi_stream_ptr->header.header_size < sizeof(TPIStreamHeader)) {
        DbgPrintEx(0,0,"Warning: TPI header_size (%u) < sizeof(TPIStreamHeader) (%zu)\n",
                tpi_stream_ptr->header.header_size, sizeof(TPIStreamHeader)); 
        return TPI_FORMAT_ERROR;
    }

    if (tpi_stream_ptr->header.type_index_end <= tpi_stream_ptr->header.type_index_begin) {
        DbgPrintEx(0,0,"Warning: TPI type_index_end (0x%X) <= type_index_begin (0x%X)\n",
                 tpi_stream_ptr->header.type_index_end, 
                 tpi_stream_ptr->header.type_index_begin);
        return TPI_FORMAT_ERROR;
    }
    if (tpi_stream_ptr->header.header_size + tpi_stream_ptr->header.type_record_bytes !=
        tpi_stream_ptr->size) {
        DbgPrintEx(0,0,"Error: TPI header_size + type_record_bytes != TPI stream "
                         "total size.\n");
        return TPI_FORMAT_ERROR;
    }

    tpi_stream_ptr->parsed_header = TRUE;
    return TPI_OK;
}

 TPIResult process_one_type_record_from_stream(
    TPIContext* ctx, const UCHAR** current_record_ptr_in_stream_addr,
    ULONG* offset_in_records_data_block_addr,
    ULONG total_type_record_bytes_in_block,
    ULONG* current_type_index_being_parsed_addr) {
    const UCHAR* current_byte_ptr = *current_record_ptr_in_stream_addr;
    ULONG current_offset_val = *offset_in_records_data_block_addr;

     if (current_offset_val + sizeof(USHORT) > total_type_record_bytes_in_block) {
        // fprintf(stderr, "TPI Parse Error: Not enough data for reclen at offset %u (total %u)\n", current_offset_val, total_type_record_bytes_in_block);
        return TPI_BUFFER_TOO_SMALL;
    }
    USHORT reclen_field_value = *(USHORT*)current_byte_ptr;

    if (reclen_field_value < sizeof(USHORT)) {
        // fprintf(stderr, "TPI Parse Error: Invalid reclen_field_value %u at offset %u\n", reclen_field_value, current_offset_val);
        return TPI_FORMAT_ERROR;
    }

    ULONG current_record_total_on_stream_size = sizeof(USHORT) + reclen_field_value;
    if (current_offset_val + current_record_total_on_stream_size > total_type_record_bytes_in_block) {
        // fprintf(stderr, "TPI Parse Error: Record (reclen %u) size %u exceeds block boundary at offset %u (total %u)\n", reclen_field_value, current_record_total_on_stream_size, current_offset_val, total_type_record_bytes_in_block);
        return TPI_BUFFER_TOO_SMALL;
    }

    /*
    struct RecordHeader {
      uint16_t RecordLen;  // Record length, not including this 2-byte field.
      uint16_t RecordKind; // Record kind enum.
    };
    */
    RawTypeRecord raw_record_data;
    raw_record_data.reclen = reclen_field_value - sizeof(USHORT);
    raw_record_data.type = *(USHORT*)(current_byte_ptr + sizeof(USHORT));
    raw_record_data.data_ptr = current_byte_ptr + sizeof(USHORT) + sizeof(USHORT);

    struct codeview_custom_type* parsed_cv_type = NULL;
    TPIResult res = parse_raw_record_to_cv_type(
        *current_type_index_being_parsed_addr, raw_record_data, &parsed_cv_type);

    if (res != TPI_OK) {
        free_codeview_custom_type(parsed_cv_type);
        return res;
    }

    res = add_type(ctx, parsed_cv_type);
    if (res != TPI_OK) {
        free_codeview_custom_type(parsed_cv_type);
        return res;
    }

    *current_record_ptr_in_stream_addr += current_record_total_on_stream_size;
    *offset_in_records_data_block_addr += current_record_total_on_stream_size;
    (*current_type_index_being_parsed_addr)++;

    if (*offset_in_records_data_block_addr < total_type_record_bytes_in_block &&
        *offset_in_records_data_block_addr % 4 != 0) {
        ULONG padding_needed = 4 - (*offset_in_records_data_block_addr % 4);
        if (*offset_in_records_data_block_addr + padding_needed <= total_type_record_bytes_in_block) {
            *current_record_ptr_in_stream_addr += padding_needed;
            *offset_in_records_data_block_addr += padding_needed;
        }
        else {
            ULONG remaining_in_block = total_type_record_bytes_in_block - *offset_in_records_data_block_addr;
            *current_record_ptr_in_stream_addr += remaining_in_block;
            *offset_in_records_data_block_addr += remaining_in_block;
        }
    }
    return TPI_OK;
}


TPIResult parse_all_type_records(const TPIStream* tpi_stream_ptr, TPIContext* ctx) {
    if (!tpi_stream_ptr || !tpi_stream_ptr->parsed_header || tpi_stream_ptr->header.type_record_bytes == 0) {
        return TPI_OK;
    }

    const UCHAR* type_records_data_start = tpi_stream_ptr->data + tpi_stream_ptr->header.header_size;
    ULONG current_offset_in_block = 0;
    ULONG current_type_idx = tpi_stream_ptr->header.type_index_begin;
    const UCHAR* current_ptr_in_stream = type_records_data_start;

    ULONG types_parsed_count = 0;
    ULONG loop_sanity_count = 0;
    const ULONG MAX_LOOPS =
        tpi_stream_ptr->header.type_index_end > tpi_stream_ptr->header.type_index_begin
        ? (tpi_stream_ptr->header.type_index_end - tpi_stream_ptr->header.type_index_begin) + 1000
        : 200000;

    while (current_offset_in_block < tpi_stream_ptr->header.type_record_bytes &&
        loop_sanity_count < MAX_LOOPS) {
        if (tpi_stream_ptr->header.type_index_end != 0 &&
            current_type_idx >= tpi_stream_ptr->header.type_index_end) {
            break;
        }

        TPIResult res = process_one_type_record_from_stream(
            ctx, &current_ptr_in_stream, &current_offset_in_block,
            tpi_stream_ptr->header.type_record_bytes, &current_type_idx);
        if (res != TPI_OK) {
            DbgPrintEx(0, 0, "Error parsing type record at/after index 0x%X, offset %u. "
                "Aborting TPI parse.\n",
                current_type_idx, current_offset_in_block);
            return res;
        }
        types_parsed_count++;
        loop_sanity_count++;
    }
    
    if (loop_sanity_count >= MAX_LOOPS &&
        current_offset_in_block < tpi_stream_ptr->header.type_record_bytes) {
        DbgPrintEx(0,0,"Warning: TPI parsing stopped due to sanity limit. Processed %u "
            "types.\n",
            types_parsed_count);
        return TPI_PARSE_ERROR;
    }
    if (current_offset_in_block > tpi_stream_ptr->header.type_record_bytes) {
        DbgPrintEx(0,0,"Error: TPI parsing overran type_record_bytes. Offset %u, Expected "
            "%u.\n",
            current_offset_in_block, tpi_stream_ptr->header.type_record_bytes);
        return TPI_PARSE_ERROR;
    }

    
    if (current_offset_in_block < tpi_stream_ptr->header.type_record_bytes &&
        !(tpi_stream_ptr->header.type_index_end != 0 &&
            current_type_idx >= tpi_stream_ptr->header.type_index_end)) {
        DbgPrintEx(0,0,"Warning: TPI parsing finished prematurely. Offset %u/%u. Final "
            "type_idx 0x%X (End 0x%X)\n",
            current_offset_in_block, tpi_stream_ptr->header.type_record_bytes,
            current_type_idx, tpi_stream_ptr->header.type_index_end);
        return TPI_PARSE_ERROR;
    }
    return TPI_OK;
}


 void print_indent(PrintContext* pctx) {
    for (int i = 0; i < pctx->indent_level; ++i) {
        DbgPrintEx(0,0,"    ");
    }
}

// Forward declarations for new print_details and print_subtype functions
 TPIResult print_details_cv_lf_class_structure(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 TPIResult print_details_cv_lf_enum(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 TPIResult print_details_cv_lf_modifier(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 TPIResult print_details_cv_lf_typedef(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 TPIResult print_details_cv_lf_arglist(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 TPIResult print_details_cv_lf_array(PrintContext* pctx, const struct codeview_custom_type* cv_type);
 void print_cv_field_list_formatted(PrintContext* pctx, const struct codeview_custom_type* cv_fieldlist_type);

 void print_subtype_lf_member_stmember(PrintContext* pctx, const struct codeview_subtype* subtype);
 void print_subtype_lf_enumerate(PrintContext* pctx, const struct codeview_subtype* subtype);
 void print_subtype_lf_onemethod(PrintContext* pctx, const struct codeview_subtype* subtype);
 void print_subtype_lf_method(PrintContext* pctx, const struct codeview_subtype* subtype);


 TPIResult print_details_cv_lf_array(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    if (!pctx || !cv_type || cv_type->kind != LF_ARRAY) {
        return TPI_INVALID_PARAMETER;
    }

    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    char type_name_buffer[MAX_TYPE_NAME_BUF];

    print_indent(pctx);
    DbgPrintEx(0,0,"size: %s%llu",
        cv_type->lf_array.length_in_bytes.neg ? "-" : "",
        cv_type->lf_array.length_in_bytes.num);

    DbgPrintEx(0,0,", index type: 0x%04X (", cv_type->lf_array.index_type);
    if (get_friendly_primitive_name(cv_type->lf_array.index_type, type_name_buffer, sizeof(type_name_buffer))) { //
        DbgPrintEx(0,0,"%s", type_name_buffer);
    }
    else {
        if (get_type_name_str_by_index(tpi_ctx, cv_type->lf_array.index_type, type_name_buffer, sizeof(type_name_buffer)) == TPI_OK) { //
            DbgPrintEx(0,0,"`%s`", type_name_buffer);
        }
        else {
            DbgPrintEx(0,0,"<unknown type>");
        }
    }
    DbgPrintEx(0,0,")");

    DbgPrintEx(0,0,", element type: 0x%04X (", cv_type->lf_array.element_type);
    if (get_friendly_primitive_name(cv_type->lf_array.element_type, type_name_buffer, sizeof(type_name_buffer))) { //
        DbgPrintEx(0,0,"%s", type_name_buffer);
    }
    else {
        if (get_type_name_str_by_index(tpi_ctx, cv_type->lf_array.element_type, type_name_buffer, sizeof(type_name_buffer)) == TPI_OK) { //
            DbgPrintEx(0,0,"`%s`", type_name_buffer);
        }
        else {
            DbgPrintEx(0,0,"<unknown type>");
        }
    }
    DbgPrintEx(0,0,")\n");

    return TPI_OK;
}

 TPIResult print_type_record_formatted(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    if (!pctx || !cv_type)
        return TPI_INVALID_PARAMETER;

    char leaf_name_buffer[64];
    get_leaf_type_name_str(cv_type->kind, leaf_name_buffer, sizeof(leaf_name_buffer));

    print_indent(pctx);

     ULONG total_record_size_on_stream = cv_type->original_record_reclen + sizeof(USHORT);
    DbgPrintEx(0,0,"0x%04x | %s [size = %u]", cv_type->_index, leaf_name_buffer,
        total_record_size_on_stream);

    char* name_ptr = NULL;
    if (cv_type->kind == LF_CLASS || cv_type->kind == LF_STRUCTURE) name_ptr = cv_type->lf_structure.name;
    else if (cv_type->kind == LF_ENUM) name_ptr = cv_type->lf_enum.name;
    else if (cv_type->kind == LF_TYPEDEF) name_ptr = cv_type->lf_typedef.name;

    if (name_ptr && name_ptr[0] != '\0') {
        DbgPrintEx(0,0," `%s`", name_ptr);
    }
    DbgPrintEx(0,0,"\n");

    if (!pctx->show_details)
        return TPI_OK;

    pctx->indent_level++;
    TPIResult res = TPI_OK;
    switch (cv_type->kind) {
    case LF_CLASS:
    case LF_STRUCTURE:
        res = print_details_cv_lf_class_structure(pctx, cv_type);
        break;
    case LF_ENUM:
        res = print_details_cv_lf_enum(pctx, cv_type);
        break;
    case LF_MODIFIER:
        res = print_details_cv_lf_modifier(pctx, cv_type);
        break;
    case LF_FIELDLIST:
        print_cv_field_list_formatted(pctx, cv_type);
        break;
    case LF_TYPEDEF:
        res = print_details_cv_lf_typedef(pctx, cv_type);
        break;
    case LF_ARGLIST:
        res = print_details_cv_lf_arglist(pctx, cv_type);
        break;
    case LF_ARRAY:
        res = print_details_cv_lf_array(pctx, cv_type);
        break;
    default:
        break;
    }
    pctx->indent_level--;
    return res;
}

 TPIResult print_details_cv_lf_class_structure(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    char name_buffer[MAX_TYPE_NAME_BUF];
    const char* unique_name = cv_type->lf_structure.unique_name;

    if (unique_name && unique_name[0] != '\0') {
        print_indent(pctx);
        DbgPrintEx(0,0,"unique name: `%s`\n", unique_name);
    }

    print_indent(pctx);
    DbgPrintEx(0,0,"vtable: ");
    if (cv_type->lf_structure.vshape_idx == 0) {
        DbgPrintEx(0,0,"<no type>");
    }
    else {
        if (get_type_name_str_by_index(tpi_ctx, cv_type->lf_structure.vshape_idx, name_buffer, sizeof(name_buffer)) == TPI_OK) {
            DbgPrintEx(0,0,"0x%x (`%s`)", cv_type->lf_structure.vshape_idx, name_buffer);
        }
        else {
            DbgPrintEx(0,0,"0x%x (<error fetching name>)", cv_type->lf_structure.vshape_idx);
        }
    }

    DbgPrintEx(0,0,", base list: ");
    if (cv_type->lf_structure.derived_from_idx == 0) {
        DbgPrintEx(0,0,"<no type>");
    }
    else {
        if (get_type_name_str_by_index(tpi_ctx, cv_type->lf_structure.derived_from_idx, name_buffer, sizeof(name_buffer)) == TPI_OK) {
            DbgPrintEx(0,0,"0x%x (`%s`)", cv_type->lf_structure.derived_from_idx, name_buffer);
        }
        else {
            DbgPrintEx(0,0,"0x%x (<error fetching name>)", cv_type->lf_structure.derived_from_idx);
        }
    }

    DbgPrintEx(0,0,", field list: ");
    if (cv_type->lf_structure.field_list_idx != 0) {
        DbgPrintEx(0,0,"0x%x", cv_type->lf_structure.field_list_idx);
    }
    else {
        DbgPrintEx(0,0,"<no type>");
    }
    DbgPrintEx(0,0,"\n");

    print_indent(pctx);
    DbgPrintEx(0,0,"options: ");
    char options_string_buffer[256] = { 0 };
    BOOL is_first_option = TRUE;
    USHORT properties = cv_type->lf_structure.properties;
        
#define APPEND_OPT_DETAIL(prop_flag, prop_name_str) \
    if (properties & (prop_flag)) { \
        if (!is_first_option) { \
            RtlStringCchCatA(options_string_buffer, (sizeof(options_string_buffer)), " | "); \
        } \
        RtlStringCchCatA(options_string_buffer, (sizeof(options_string_buffer)), (prop_name_str)); \
        is_first_option = FALSE; \
    }

    APPEND_OPT_DETAIL(CV_PPROP_HASCTORORDTOR, "has ctor/dtor");
    APPEND_OPT_DETAIL(CV_PPROP_HASUNIQUENAME, "has unique name");
    APPEND_OPT_DETAIL(CV_PPROP_PACKED, "packed");
    APPEND_OPT_DETAIL(CV_PPROP_ISNESTED, "is nested");
    APPEND_OPT_DETAIL(CV_PPROP_FORWARDREF, "forward ref");
    APPEND_OPT_DETAIL(CV_PPROP_SCOPED, "scoped");

    if (strlen(options_string_buffer) > 0) {
        DbgPrintEx(0,0,"%s", options_string_buffer);
    }
    else {
        DbgPrintEx(0,0,"<none>");
    }
#undef APPEND_OPT_DETAIL 

    DbgPrintEx(0,0,", sizeof %s%llu",
        cv_type->lf_structure.structure_length.neg ? "-" : "",
        cv_type->lf_structure.structure_length.num);
    DbgPrintEx(0,0,"\n");
    return TPI_OK;
}

 TPIResult print_details_cv_lf_enum(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    char underlying_friendly_name[MAX_TYPE_NAME_BUF];
    const char* unique_name = cv_type->lf_enum.unique_name;

    print_indent(pctx);
    if (unique_name && unique_name[0] != '\0') {
        DbgPrintEx(0,0,"unique name: `%s`\n", unique_name);
        print_indent(pctx);
    }

    if (!get_friendly_primitive_name(
        cv_type->lf_enum.underlying_type,
        underlying_friendly_name, sizeof(underlying_friendly_name))) {
        get_type_name_str_by_index(
            tpi_ctx, cv_type->lf_enum.underlying_type,
            underlying_friendly_name, sizeof(underlying_friendly_name));
    }

    DbgPrintEx(0,0,"field list: 0x%x, underlying type: 0x%04x (%s)\n",
        cv_type->lf_enum.fieldlist_idx, cv_type->lf_enum.underlying_type,
        underlying_friendly_name);

    BOOL has_options = TRUE;
    char options_string[256] = "";
    options_string[0] = '\0';
    USHORT properties = cv_type->lf_enum.properties;

    if (properties & CV_PPROP_HASUNIQUENAME) {
        // strcat(options_string, "has unique name");
        RtlStringCchCatA(options_string, sizeof(options_string), "has unique name");
        has_options = TRUE;
    }
    if (properties & CV_PPROP_ISNESTED) {
        if (has_options) strcat(options_string, " | ");
        RtlStringCchCatA(options_string, sizeof(options_string), "is nested");
        has_options = TRUE;
    }
    if (properties & CV_PPROP_FORWARDREF) {
        if (has_options) strcat(options_string, " | ");
        RtlStringCchCatA(options_string, sizeof(options_string), "forward ref");
        has_options = TRUE;
    }

    if (has_options) {
        print_indent(pctx);
        DbgPrintEx(0,0,"options: %s\n", options_string);
    }
    return TPI_OK;
}

 TPIResult print_details_cv_lf_modifier(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    char name_buffer[MAX_TYPE_NAME_BUF];
    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    get_type_name_str_by_index(tpi_ctx,
        cv_type->lf_modifier.base_type,
        name_buffer, sizeof(name_buffer));
    print_indent(pctx);
    DbgPrintEx(0,0,"Modified Type = 0x % 04x(% s), Modifiers = 0x % X\n",
        cv_type->lf_modifier.base_type, name_buffer,
        cv_type->lf_modifier.modifier);
    return TPI_OK;
}

 TPIResult print_details_cv_lf_typedef(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    char name_buffer[MAX_TYPE_NAME_BUF];
    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    get_type_name_str_by_index(tpi_ctx,
        cv_type->lf_typedef.underlying_type_idx,
        name_buffer, sizeof(name_buffer));
    print_indent(pctx);
    DbgPrintEx(0,0,"Aliased Type = 0x%04x (%s)\n",
        cv_type->lf_typedef.underlying_type_idx, name_buffer);
    return TPI_OK;
}

 TPIResult print_details_cv_lf_arglist(PrintContext* pctx, const struct codeview_custom_type* cv_type) {
    TPIContext* tpi_ctx = pctx->_tpi_ctx;
    print_indent(pctx);
    DbgPrintEx(0,0,"Argument Count = %u\n", cv_type->lf_arglist.num_entries);
    char name_buffer[MAX_TYPE_NAME_BUF];
    for (ULONG i = 0; i < cv_type->lf_arglist.num_entries; ++i) {
        ULONG arg_type_idx = cv_type->lf_arglist.args[i];
        get_type_name_str_by_index(tpi_ctx, arg_type_idx, name_buffer, sizeof(name_buffer));
        print_indent(pctx);
        DbgPrintEx(0,0,"Argument %u: 0x%04x (`%s`)\n", i, arg_type_idx, name_buffer);
    }
    return TPI_OK;
}


 void print_subtype_lf_member_stmember(PrintContext* pctx, const struct codeview_subtype* subtype) {
    char attributes_string_buffer[64];
    char type_display_str[MAX_TYPE_NAME_BUF + 20];
    char friendly_name[MAX_TYPE_NAME_BUF];
    const char* member_name_str;
    USHORT field_attributes;
    ULONG type_idx;
    const char* subtype_name_str;

    if (subtype->kind == LF_MEMBER) {
        subtype_name_str = "LF_MEMBER";
        member_name_str = subtype->lf_member.name;
        field_attributes = subtype->lf_member.attributes;
        type_idx = subtype->lf_member.type;
    }
    else { // LF_STMEMBER
        subtype_name_str = "LF_STMEMBER";
        member_name_str = subtype->lf_static_member.name;
        field_attributes = subtype->lf_static_member.attributes;
        type_idx = subtype->lf_static_member.type;
    }

    format_member_attributes_str(field_attributes, attributes_string_buffer, sizeof(attributes_string_buffer));

    if (get_friendly_primitive_name(type_idx, friendly_name, sizeof(friendly_name))) {
        // snprintf(type_display_str, sizeof(type_display_str), "0x%04x (%s)", type_idx, friendly_name);
        RtlStringCchPrintfA(type_display_str, sizeof(type_display_str), "0x%04x (%s)", type_idx, friendly_name);
    }
    else {
        if (get_type_name_str_by_index(pctx->_tpi_ctx, type_idx, friendly_name, sizeof(friendly_name)) == TPI_OK) {
            RtlStringCchPrintfA(type_display_str, sizeof(type_display_str), "0x%04x (`%s`)", type_idx, friendly_name);
        }
        else {
            RtlStringCchPrintfA(type_display_str, sizeof(type_display_str), "0x%04x", type_idx);
        }
    }

    print_indent(pctx);
    DbgPrintEx(0,0,"- %s [name = `%s`, Type = %s", subtype_name_str, member_name_str ? member_name_str : "<null>", type_display_str);
    if (subtype->kind == LF_MEMBER) {
        DbgPrintEx(0,0,", offset = %s%lld", subtype->lf_member.offset.neg ? "-" : "", subtype->lf_member.offset.num);
    }
    DbgPrintEx(0,0,", attrs = %s]\n", attributes_string_buffer);
}

 void print_subtype_lf_enumerate(PrintContext* pctx, const struct codeview_subtype* subtype) {
    print_indent(pctx);
    DbgPrintEx(0,0,"- LF_ENUMERATE [name = `%s` = %s%lld""]\n",
        subtype->lf_enumerate.name ? subtype->lf_enumerate.name : "<null>",
        subtype->lf_enumerate.value.neg ? "-" : "",
        subtype->lf_enumerate.value.num);
}

 void print_subtype_lf_onemethod(PrintContext* pctx, const struct codeview_subtype* subtype) {
    char attributes_string_buffer[64];
    format_method_attributes_str(subtype->lf_onemethod.method_attribute, attributes_string_buffer, sizeof(attributes_string_buffer));

    char type_name_buffer[MAX_TYPE_NAME_BUF];
    get_type_name_str_by_index(pctx->_tpi_ctx, subtype->lf_onemethod.method_type, type_name_buffer, sizeof(type_name_buffer));

    print_indent(pctx);
    DbgPrintEx(0,0,"- LF_ONEMETHOD [name = `%s`]\n", subtype->lf_onemethod.name ? subtype->lf_onemethod.name : "<null>");
    print_indent(pctx);
    DbgPrintEx(0,0,"      type = 0x%04x (`%s`), vftable offset = %d, attrs = %s\n",
        subtype->lf_onemethod.method_type, type_name_buffer,
        subtype->lf_onemethod.vtable_base_offset, // This was vbaseoff from spec
        attributes_string_buffer);
}

 void print_subtype_lf_method(PrintContext* pctx, const struct codeview_subtype* subtype) {
    char method_list_name_buffer[MAX_TYPE_NAME_BUF];
    get_type_name_str_by_index(pctx->_tpi_ctx, subtype->lf_method.method_list, method_list_name_buffer, sizeof(method_list_name_buffer));

    print_indent(pctx);
    DbgPrintEx(0,0,"- LF_METHOD [name = `%s`, # overloads = %u, overload list = 0x%x (`%s`)]\n",
        subtype->lf_method.name ? subtype->lf_method.name : "<null>",
        subtype->lf_method.count,
        subtype->lf_method.method_list,
        method_list_name_buffer);
}


 void print_cv_field_list_formatted(PrintContext* pctx, const struct codeview_custom_type* cv_fieldlist_type) {
    if (!pctx || !cv_fieldlist_type || cv_fieldlist_type->kind != LF_FIELDLIST) {
        if (pctx && cv_fieldlist_type) {
            print_indent(pctx);
            DbgPrintEx(0,0,"(Invalid call to print_cv_field_list_formatted for type 0x%X, leaf 0x%X)\n",
                cv_fieldlist_type->_index, cv_fieldlist_type->kind);
        }
        return;
    }
    if (!cv_fieldlist_type->lf_fieldlist.subtypes || cv_fieldlist_type->lf_fieldlist.length == 0) {
        // DbgPrintEx(0,0,"(Field list is empty)\n");
        return;
    }

    struct codeview_subtype* current_subtype = cv_fieldlist_type->lf_fieldlist.subtypes;
    while (current_subtype) {
        switch (current_subtype->kind) {
        case LF_MEMBER:
        case LF_STMEMBER:
            print_subtype_lf_member_stmember(pctx, current_subtype);
            break;
        case LF_ENUMERATE:
            print_subtype_lf_enumerate(pctx, current_subtype);
            break;
        case LF_ONEMETHOD:
            print_subtype_lf_onemethod(pctx, current_subtype);
            break;
        case LF_METHOD:
            print_subtype_lf_method(pctx, current_subtype);
            break;
        default:
        {
            char leaf_name_buffer[64];
            get_leaf_type_name_str(current_subtype->kind, leaf_name_buffer, sizeof(leaf_name_buffer));
            print_indent(pctx);
            DbgPrintEx(0,0,"- %s (Unhandled sub-field 0x%04X in FL 0x%X. Printing for this subtype not implemented.)\n",
                leaf_name_buffer, current_subtype->kind, cv_fieldlist_type->_index);
        }
        break;
        }
        current_subtype = current_subtype->next;
    }
}


 void display_focused_types(TPIContext* ctx) {
    PrintContext pctx = {.indent_level = 1,
                         .max_depth = 5,
                         .show_details = TRUE,
                         ._tpi_ctx = ctx };
    DbgPrintEx(0, 0, "begin display_focused_types.\n");

    int displayed_count = 0; 

    for (int i = 0; i < ctx->count; i++) {

        struct codeview_custom_type* current_cv_type = ctx->types[i];

         if (current_cv_type) {
            if (current_cv_type->kind == LF_FIELDLIST ||
                current_cv_type->kind == LF_ENUM ||
                current_cv_type->kind == LF_CLASS ||
                current_cv_type->kind == LF_STRUCTURE ||
                current_cv_type->kind == LF_ARRAY) {
                print_type_record_formatted(&pctx, current_cv_type);
                displayed_count++;
            }
        }
    }
}

 LONG KpdbTravelTPICodeViewAndFindMemberOffset(TPIContext* ctx, PCHAR StructName, PCHAR MemberName);
 struct codeview_custom_type* find_struct_by_name(TPIContext* ctx, PCHAR StructName);
 LONG find_member_offset_in_fieldlist(TPIContext* ctx, ULONG fieldlist_idx, PCHAR MemberName);

 struct codeview_custom_type* find_struct_by_name(TPIContext* ctx, PCHAR StructName) {
     if (!ctx || !StructName) {
         return NULL;
     }

     struct codeview_custom_type* found_forward_ref = NULL;

     for (int i = 0; i < ctx->count; i++) {
         struct codeview_custom_type* current_type = ctx->types[i];
         if (current_type) {
             char* current_type_name = NULL;
             USHORT current_type_properties = 0;

             if (current_type->kind == LF_CLASS || current_type->kind == LF_STRUCTURE) {
                 current_type_name = current_type->lf_structure.name;
                 current_type_properties = current_type->lf_structure.properties;
             }
             else if (current_type->kind == LF_ENUM) {
                 current_type_name = current_type->lf_enum.name;
                 current_type_properties = current_type->lf_enum.properties;
             }
             else if (current_type->kind == LF_TYPEDEF) {
                 current_type_name = current_type->lf_typedef.name;

                 struct codeview_custom_type* underlying_type = find_type_by_index(ctx, current_type->lf_typedef.underlying_type_idx);
                 if (underlying_type && (underlying_type->kind == LF_CLASS || underlying_type->kind == LF_STRUCTURE || underlying_type->kind == LF_ENUM)) {

                     if (underlying_type->kind == LF_CLASS || underlying_type->kind == LF_STRUCTURE) {
                         current_type_name = underlying_type->lf_structure.name;
                         current_type_properties = underlying_type->lf_structure.properties;
                     }
                     else {
                         current_type_name = underlying_type->lf_enum.name;
                         current_type_properties = underlying_type->lf_enum.properties;
                     }
                 }
                 else {
                     current_type_name = NULL;
                 }
             }

             if (current_type_name && strcmp(current_type_name, StructName) == 0) {

                 if (current_type_properties & CV_PPROP_FORWARDREF) {

                     if (found_forward_ref == NULL) {
                         found_forward_ref = current_type;
                     }
                 }
                 else {
                     return current_type;
                 }
             }
         }
     }
     return NULL;
 }

 LONG find_member_offset_in_fieldlist(TPIContext* ctx, ULONG fieldlist_idx, PCHAR MemberName) {
     struct codeview_custom_type* fieldlist_type = find_type_by_index(ctx, fieldlist_idx);
     if (!fieldlist_type || fieldlist_type->kind != LF_FIELDLIST) {
         return -1;
     }

     struct codeview_subtype* current_subtype = fieldlist_type->lf_fieldlist.subtypes;
     while (current_subtype) {
         if (current_subtype->kind == LF_MEMBER) {
             if (current_subtype->lf_member.name && strcmp(current_subtype->lf_member.name, MemberName) == 0) {
                 return (LONG)current_subtype->lf_member.offset.num;
             }
         }
         current_subtype = current_subtype->next;
     }
     return -1;
 }

BOOL KpdbTravelTPICodeView(PVOID pdbfile) {
    DbgPrintEx(0,0, "Start reading TPI Stream.....\n");

    #define TPI_STREAM_INDEX 2 

    PVOID tpi_stream_ptr = NULL;
    SIZE_T tpi_stream_size = 0;
    TPIStreamHeader* tpi_header_ptr = NULL;

    TPIStream tpi_stream;
    memset(&tpi_stream, 0, sizeof(TPIStream));
    TPIContext tpi_context;
    memset(&tpi_context, 0, sizeof(TPIContext));
    
    StreamData* streams = NULL;
    DWORD streams_count = 0;
    BOOL success_status = FALSE;


    streams = KpdbGetPDBStreams(pdbfile, &streams_count);
    if (!streams) {
        DbgPrintEx(0, 0, "Error: KpdbGetPDBStreams failed.\n");
        free_tpi_context(&tpi_context);
        return FALSE;
    }

    if (streams_count > TPI_STREAM_INDEX) {
        tpi_stream_ptr = streams[TPI_STREAM_INDEX].StreamPointer;
        tpi_stream_size = streams[TPI_STREAM_INDEX].StreamSize;
    } else {
        DbgPrintEx(0, 0, "Error: TPI stream not found or insufficient streams.\n");
        goto cleanup;
    }

    if (tpi_stream_ptr == NULL || tpi_stream_size == 0) {
        DbgPrintEx(0, 0,"Error: TPI stream data is invalid.\n");
        goto cleanup;
    }

    if (tpi_stream_size < sizeof(TPIStreamHeader)) {
        DbgPrintEx(0, 0, "Error: TPI stream size is too small for header.\n");
        goto cleanup;
    }

    tpi_header_ptr = (TPIStreamHeader*)tpi_stream_ptr;
    tpi_stream.data = (UCHAR*)tpi_stream_ptr;
    tpi_stream.size = tpi_stream_size;

    if (check_tpi_header(&tpi_stream) != TPI_OK) {
        DbgPrintEx(0, 0, "Error: check_tpi_header failed.\n");
        goto cleanup;
    }

    DbgPrintEx(0, 0, "TPI Version: 0x%X\n", tpi_header_ptr->version);
    DbgPrintEx(0, 0, "TPI Header Size: %u\n", tpi_header_ptr->header_size);
    DbgPrintEx(0, 0, "TPI Type Index Begin: %u\n", tpi_header_ptr->type_index_begin);
    DbgPrintEx(0, 0, "TPI Type Index End: %u\n", tpi_header_ptr->type_index_end);
    DbgPrintEx(0, 0, "TPI Types Data Size: %u\n", tpi_header_ptr->type_record_bytes);       
     
    TPIResult res = parse_all_type_records(&tpi_stream, &tpi_context);
    if (res != TPI_OK) {
        DbgPrintEx(0, 0, "Error: parse_all_type_records failed. code %d\n", (int)res);
        goto cleanup;
    }
 
    display_focused_types(&tpi_context);
    DbgPrintEx(0, 0, "Finished reading TPI Stream....\n");
    
    success_status = TRUE;

cleanup:    
    for (int i = 0; i < streams_count; i++) {
        ExFreePool(streams[i].StreamPointer);
    }

    ExFreePool(streams);
    return success_status;
}

LONG KpdbTravelTPICodeViewAndFindMemberOffset(TPIContext* ctx, PCHAR StructName, PCHAR MemberName) {
    if (!ctx || !StructName || !MemberName)
         return -1;

    struct codeview_custom_type* struct_type = find_struct_by_name(ctx, StructName);
    if (!struct_type) {
        DbgPrintEx(0, 0, "[KPDB] KpdbTravelTPICodeViewAndFindMemberOffset - Struct '%s' not found.\n", StructName);
        return -1;
    }

    if (struct_type->kind == LF_CLASS || struct_type->kind == LF_STRUCTURE) {
        ULONG field_list_idx = struct_type->lf_structure.field_list_idx;
        if (field_list_idx == 0) {
            DbgPrintEx(0, 0, "[KPDB] KpdbTravelTPICodeViewAndFindMemberOffset - Struct '%s' has no field list.\n", StructName);
            return -1;
        }
        LONG offset = find_member_offset_in_fieldlist(ctx, field_list_idx, MemberName);
        if (offset != -1) {
            DbgPrintEx(0, 0, "[KPDB] Found offset for %s::%s: %d\n", StructName, MemberName, offset);
            return offset;
        }
        else {
            DbgPrintEx(0, 0, "[KPDB] Member '%s' not found in struct '%s'.\n", MemberName, StructName);
        }
    }
    else {
        DbgPrintEx(0, 0, "[KPDB] Type '%s' is not a class or struct (kind: 0x%x).\n", StructName, struct_type->kind);
    }

    return -1;
}

LONG KpdbGetStructMemberOffset(PVOID pdbfile, PCHAR StructName, PCHAR MemberName) {
    LONG offset = -1;
    PVOID tpi_stream_ptr = NULL;
    SIZE_T tpi_stream_size = 0;

    StreamData* streams = NULL;
    DWORD streams_count = 0;
    TPIContext tpi_context;
    RtlZeroMemory(&tpi_context, sizeof(TPIContext));

#define TPI_STREAM_INDEX 2

    streams = KpdbGetPDBStreams(pdbfile, &streams_count);
    if (!streams) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetStructMemberOffset - KpdbGetPDBStreams failed.\n");
        return -1;
    }

    if (streams_count > TPI_STREAM_INDEX) {
        tpi_stream_ptr = streams[TPI_STREAM_INDEX].StreamPointer;
        tpi_stream_size = streams[TPI_STREAM_INDEX].StreamSize;
    }
    else {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetStructMemberOffset - TPI stream not found or insufficient streams.\n");
        goto cleanup;
    }

    if (tpi_stream_ptr == NULL || tpi_stream_size == 0) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetStructMemberOffset - TPI stream data is invalid.\n");
        goto cleanup;
    }

    TPIStream tpi_stream;
    RtlZeroMemory(&tpi_stream, sizeof(TPIStream));
    tpi_stream.data = (UCHAR*)tpi_stream_ptr;
    tpi_stream.size = tpi_stream_size;

    if (check_tpi_header(&tpi_stream) != TPI_OK) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetStructMemberOffset - check_tpi_header failed.\n");
        goto cleanup;
    }

    if (parse_all_type_records(&tpi_stream, &tpi_context) != TPI_OK) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetStructMemberOffset - parse_all_type_records failed.\n");
        goto cleanup;
    }

    offset = KpdbTravelTPICodeViewAndFindMemberOffset(&tpi_context, StructName, MemberName);

cleanup:
    for (int i = 0; i < streams_count; i++) {
        if (streams[i].StreamPointer) {
            ExFreePool(streams[i].StreamPointer);
        }
    }
    if (streams) {
        ExFreePool(streams);
    }
    return offset;
}

