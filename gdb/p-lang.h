/* Pascal language support definitions for GDB, the GNU debugger.

   Copyright (C) 2000, 2005, 2006, 2007, 2008 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* This file is derived from c-lang.h */

struct value;

/* Defined in p-lang.c */
extern const char *pascal_main_name (void);

extern int pascal_parse (void);	/* Defined in p-exp.y */

extern void pascal_error (char *);	/* Defined in p-exp.y */

/* Defined in p-typeprint.c */
extern void pascal_print_type (struct type *, char *, struct ui_file *, int, int);

extern void pascal_print_typedef (struct type *, struct symbol *,
				  struct ui_file *);

extern int pascal_val_print (struct type *, const gdb_byte *, int,
			     CORE_ADDR, struct ui_file *, int, int,
			     int, enum val_prettyprint);

extern int pascal_value_print (struct value *, struct ui_file *, int, enum val_prettyprint);

extern void pascal_type_print_method_args (char *, char *,
					   struct ui_file *);

/* These are in p-lang.c: */

extern int 
  is_pascal_string_type (struct type *, int *, int *, int *, int *, char **);

extern void pascal_printchar (int, struct ui_file *);

extern void pascal_printstr (struct ui_file *, const gdb_byte *,
			     unsigned int, int, int);

extern struct type **const (pascal_builtin_types[]);

/* These are in p-typeprint.c: */

extern void
  pascal_type_print_base (struct type *, struct ui_file *, int, int);

extern void
  pascal_type_print_varspec_prefix (struct type *, struct ui_file *, int, int);

/* These are in cp-valprint.c */

extern int vtblprint;		/* Controls printing of vtbl's */

extern int static_field_print;

extern void pascal_object_print_value_fields (struct type *, const gdb_byte *,
					      CORE_ADDR, struct ui_file *,
					      int, int, enum val_prettyprint,
					      struct type **, int);

extern int pascal_object_is_vtbl_ptr_type (struct type *);

extern int pascal_object_is_vtbl_member (struct type *);
