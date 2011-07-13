/*
 pylibnet - Python module for the libnet packet injection library
 Copyright (C) 2009  Nadeem Douba

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 Nadeem Douba <ndouba at gmail dot com>
 348 Patricia Ave, Ottawa, ON, K1Z 6G6
 Canada
*/

#include <Python.h>
#include "structmember.h"

// Let's avoid the redefinition error shall we :)
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

#include <libnet.h>
#include "constants.h"

static PyObject *PyErr_LibnetError;

#include "context.c"
#include "plist.c"

static PyMethodDef module_methods[] = {
	{NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initlibnet(void) 
{
	int i = 0;
	PyObject *m, *m2;

	if (PyType_Ready(&context_Type) < 0)
		return;

	plist_Type.tp_base = &PyList_Type;
	if (PyType_Ready(&plist_Type) < 0)
		return;

	m = Py_InitModule3("libnet", module_methods, "Python module for the Libnet packet injection library.");

	if (m == NULL)
		return;

	PyErr_LibnetError = PyErr_NewException("libnet.error", NULL, NULL);
	Py_INCREF(PyErr_LibnetError);
	PyModule_AddObject(m, "error", PyErr_LibnetError);

	Py_INCREF(&context_Type);
	PyModule_AddObject(m, "context", (PyObject *)&context_Type);

	Py_INCREF(&plist_Type);
	PyModule_AddObject(m, "plist", (PyObject *)&plist_Type);

	m2 = Py_InitModule3("libnet.constants", module_methods, "Constants");
	Py_INCREF(m2);

	while(libnet_constants[i].c_name != NULL) {
		PyModule_AddIntConstant(m2, libnet_constants[i].c_name, libnet_constants[i].value);
		i++;
	}

	PyModule_AddObject(m, "constants", m2);

}
