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

#define PYLIBNET_CONTEXT "libnet.context"


typedef struct {
	PyListObject list;
} plist;

static int
plist_init(plist *self, PyObject *args, PyObject *kwargs)
{

	int errnum = 0;
	u_int16_t bport, eport;
	char *token_list = NULL;
	libnet_t l;
	libnet_plist_t *pl = NULL;

	static char *kwlist[] = {"token_list", NULL};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", kwlist, &token_list))
		return -1;

	if (token_list == NULL) {
		PyErr_SetString(PyExc_TypeError, "argument 'token_list' must be a string");
		return -1;
	}

	if (libnet_plist_chain_new(&l, &pl, token_list) == -1) {
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(&l));
		return -1;
	}

	while((errnum = libnet_plist_chain_next_pair(pl, &bport, &eport)) == 1) {
		if (PyList_Append((PyObject *)self, Py_BuildValue("(i,i)", bport, eport)) == -1) {
			errnum = -1;
			goto fail;
		}
	}

	if (errnum == -1)
		PyErr_SetString(PyErr_LibnetError, libnet_geterror(&l));

fail:
	libnet_plist_chain_free(pl);
	return (errnum >= 0)?0:-1;

}

PyDoc_STRVAR(plist_doc,
	"plist(token_list)\n\nCreates a new port list. Port list chains are useful for TCP and UDP-based applications that need to\n"
	"send packets to a range of ports (contiguous or otherwise). The token_list accepts the following characters \"0123456789,-\"\n"
	"and is of the general format \"x - y, z\", where \"xyz\" are port numbers between 0 and 65,535.\n"
	"\nParameters:\n\n"
	"token_list - string containing the port list primitive\n"
	"\nReturns: a list object containing beginning and end port pairs or None on error.\n\n");

static PyTypeObject plist_Type = {
	PyObject_HEAD_INIT(NULL)
		0,                         /*ob_size*/
		"libnet.plist",            /*tp_name*/
		sizeof(plist),             /*tp_basicsize*/
		0,                         /*tp_itemsize*/
		0,                         /*tp_dealloc*/
		0,                         /*tp_print*/
		0,                         /*tp_getattr*/
		0,                         /*tp_setattr*/
		0,                         /*tp_compare*/
		0,                         /*tp_repr*/
		0,                         /*tp_as_number*/
		0,                         /*tp_as_sequence*/
		0,                         /*tp_as_mapping*/
		0,                         /*tp_hash */
		0,                         /*tp_call*/
		0,                         /*tp_str*/
		0,                         /*tp_getattro*/
		0,                         /*tp_setattro*/
		0,                         /*tp_as_buffer*/
		Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
		plist_doc,           /* tp_doc */
		0,		               /* tp_traverse */
		0,		               /* tp_clear */
		0,		               /* tp_richcompare */
		0,		               /* tp_weaklistoffset */
		0,		               /* tp_iter */
		0,		               /* tp_iternext */
		0,             /* tp_methods */
		0,             /* tp_members */
		0,                         /* tp_getset */
		0,                         /* tp_base */
		0,                         /* tp_dict */
		0,                         /* tp_descr_get */
		0,                         /* tp_descr_set */
		0,                         /* tp_dictoffset */
		(initproc)plist_init,      /* tp_init */
		0,                         /* tp_alloc */
		0,                 /* tp_new */
};
