/*****************************************************************************\
 *  Copyright (C) 2007-2010 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Brian Behlendorf <behlendorf1@llnl.gov>.
 *  UCRL-CODE-235197
 *
 *  This file is part of the SPL, Solaris Porting Layer.
 *  For details, see <http://github.com/behlendorf/spl/>.
 *
 *  The SPL is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  The SPL is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with the SPL.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************
 *  Solaris Porting Layer (SPL) Debug Implementation.
\*****************************************************************************/

#include <linux/kmod.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/proc_compat.h>
#include <linux/file_compat.h>
#include <sys/sysmacros.h>
#include "sys/policy.h"
#include <sys/types.h>

boolean_t secpolicy_sys_config(cred_t* c,boolean_t checkonly) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_sys_config);
boolean_t secpolicy_nfs(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_nfs);
boolean_t secpolicy_zfs(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_zfs);
boolean_t secpolicy_zinject(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_zinject);
boolean_t secpolicy_vnode_setids_setgids(cred_t* c,gid_t gid) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_setids_setgids);
boolean_t secpolicy_vnode_setid_retain(cred_t* c,boolean_t is_setuid_root) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_setid_retain);
boolean_t secpolicy_setid_clear(vattr_t* v,cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_setid_clear);
boolean_t secpolicy_vnode_any_access(cred_t* c ,struct inode* ip,uid_t owner) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_any_access);
boolean_t secpolicy_vnode_access2(cred_t* c,struct inode* ip,uid_t owner,mode_t mode1,mode_t mode2) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_access2);
boolean_t secpolicy_vnode_chown(cred_t* c,uid_t owner) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_chown);
boolean_t secpolicy_vnode_setdac(cred_t* c,uid_t owner) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_setdac);
boolean_t secpolicy_vnode_remove(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_remove);
boolean_t secpolicy_vnode_setattr(cred_t* c, struct inode* ip,vattr_t* vap,vattr_t* oldvap,int flags,int (*fp)(void *, int, cred_t *),void* znode) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_setattr); //znode_t is defined in zfs not in spl
boolean_t secpolicy_vnode_stky_modify(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_stky_modify);
boolean_t secpolicy_setid_setsticky_clear(struct inode* ip,vattr_t* attr,vattr_t* oldattr,cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_setid_setsticky_clear);
boolean_t secpolicy_basic_link(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_basic_link);
boolean_t secpolicy_vnode_create_gid(cred_t* c) {
    return B_FALSE;
}
EXPORT_SYMBOL(secpolicy_vnode_create_gid);
