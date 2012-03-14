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
#include <linux/security.h>
/*
* Possible problem:
* I'm not using passed credentials for two reasons:
* Linux kernel exposes interfaces to check for credentials of CURRENT user
* In ZFS, credentials are always obtained by calling CRED() which is defined in SPL as current_cred(), so it is the same credentials set.
* Right? There are some exceptions to this? (example: ZIL replay?)
*/
boolean_t secpolicy_sys_config(cred_t* c,boolean_t checkonly) {
    return ns_capable(current_user_ns(),CAP_SYS_ADMIN)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_sys_config);
boolean_t secpolicy_nfs(cred_t* c) {
    return ns_capable(current_user_ns(),CAP_SYS_ADMIN)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_nfs);
boolean_t secpolicy_zfs(cred_t* c) {
    return ns_capable(current_user_ns(),CAP_SYS_ADMIN)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_zfs);
boolean_t secpolicy_zinject(cred_t* c) {
    return ns_capable(current_user_ns(),CAP_SYS_ADMIN)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_zinject);
boolean_t secpolicy_vnode_setids_setgids(cred_t* c,gid_t gid) {
    if(in_group_p(gid)) return 0;
    return ns_capable(current_user_ns(),CAP_FSETID)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_setids_setgids);
boolean_t secpolicy_vnode_setid_retain(cred_t* c,boolean_t is_setuid_root) {
    return ns_capable(current_user_ns(),CAP_FSETID)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_setid_retain);
boolean_t secpolicy_setid_clear(vattr_t* v,cred_t* c) {

    if(ns_capable(current_user_ns(),CAP_FSETID)) return 0;
    if(v->va_mode & (S_ISUID|S_ISGID)) {
        v->va_mask |=AT_MODE;
        v->va_mode &= ~ (S_ISUID|S_ISGID);
    }
    return 0;
}
EXPORT_SYMBOL(secpolicy_setid_clear);
boolean_t secpolicy_vnode_any_access(cred_t* c ,struct inode* ip,uid_t owner) {
    if(crgetuid(c)==owner) return 0;
    if(ns_capable(current_user_ns(),CAP_DAC_OVERRIDE)) return 0;
    if(ns_capable(current_user_ns(),CAP_DAC_READ_SEARCH)) return 0;
    if(ns_capable(current_user_ns(),CAP_FOWNER)) return 0;
    return EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_any_access);
boolean_t secpolicy_vnode_access2(cred_t* c,struct inode* ip,uid_t owner,mode_t curmode,mode_t wantedmode) {
    mode_t missing = ~curmode & wantedmode;
    if(missing==0) return 0;

    if((missing & (~ 4 | 1 ))==0) //What are the right constants?
    {   //needs only DAC_READ_SEARCH
        if(ns_capable(current_user_ns(),CAP_DAC_READ_SEARCH)) return 0;
    }
    return ns_capable(current_user_ns(),CAP_DAC_OVERRIDE)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_access2);
boolean_t secpolicy_vnode_chown(cred_t* c,uid_t owner) {
    if(crgetuid(c)==owner) return 0;
    return ns_capable(current_user_ns(),CAP_FOWNER)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_chown);
boolean_t secpolicy_vnode_setdac(cred_t* c,uid_t owner) {
    if(crgetuid(c)==owner) return 0;
    return ns_capable(current_user_ns(),CAP_DAC_OVERRIDE)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_setdac);
boolean_t secpolicy_vnode_remove(cred_t* c) {
    return ns_capable(current_user_ns(),CAP_FOWNER)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_remove);
//znode_t is defined in ZFS, not in SPL, so it is a void*. But that's not a problem as we need it only to pass it to the zaccess function, not to work with the structure itself.
boolean_t secpolicy_vnode_setattr(cred_t* c, struct inode* ip,vattr_t* vap,vattr_t* oldvap,int flags,int (*zaccess)(void *, int, cred_t *),void* znode) {
    int mask = vap->va_mask;
    int err;
    //Tentative to make this function more readable.
    #define CHECK(arg) err=arg; if(err) return err
    if (mask & AT_MODE) {
        CHECK(secpolicy_vnode_setdac(c, oldvap->va_uid));
        CHECK(secpolicy_setid_setsticky_clear(ip, vap, oldvap, c));
     } else {
        vap->va_mode = oldvap->va_mode;
    }
    if (mask & AT_SIZE) {
        if (S_ISDIR(ip->i_mode))  return (EISDIR);
       	CHECK(zaccess(znode, S_IWUSR, c));
    }
    if (mask & (AT_UID | AT_GID)) {
       if (((mask & AT_UID) && vap->va_uid != oldvap->va_uid) ||
           ((mask & AT_GID) && vap->va_gid != oldvap->va_gid )) {
          secpolicy_setid_clear(vap, c);
          CHECK(secpolicy_vnode_setdac(c,oldvap->va_uid)); 
        }

    }
/* TODO...... Understand this chunk of code from FreeBSD and port it.
 if (mask & (AT_ATIME | AT_MTIME)) {
        / *
         * From utimes(2):
         * If times is NULL, ... The caller must be the owner of
         * the file, have permission to write the file, or be the
         * super-user.
         * If times is non-NULL, ... The caller must be the owner of
         * the file or be the super-user.
         * /
        error = secpolicy_vnode_setdac( c, oldvap->va_uid);
        if (error && (vap->va_flags & VA_UTIMES_NULL))
            error = unlocked_access(node, VWRITE, cr);
        if (error)
            return (error);
    }*/
    return 0;
}
EXPORT_SYMBOL(secpolicy_vnode_setattr);
boolean_t secpolicy_vnode_stky_modify(cred_t* c) { //NOT USED!
    return EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_stky_modify);
boolean_t secpolicy_setid_setsticky_clear(struct inode* ip,vattr_t* attr,vattr_t* oldattr,cred_t* c) {
    boolean_t requires_extrapriv=B_FALSE;
    if((attr->va_mode & S_ISGID) && !in_group_p(oldattr->va_gid)) {
        requires_extrapriv=B_TRUE;
    }
    if((attr->va_mode & S_ISUID) && !(oldattr->va_uid==crgetuid(c))) {
        requires_extrapriv=B_TRUE;
    }
    if(requires_extrapriv == B_FALSE) {
        return 0;
    }

    return ns_capable(current_user_ns(),CAP_FSETID)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_setid_setsticky_clear);
boolean_t secpolicy_basic_link(cred_t* c) {
    return ns_capable(current_user_ns(),CAP_FOWNER)?0:EACCES;
}
EXPORT_SYMBOL(secpolicy_basic_link);
boolean_t secpolicy_vnode_create_gid(cred_t* c) { //USED ONLY WITH KSID!!
    return EACCES;
}
EXPORT_SYMBOL(secpolicy_vnode_create_gid);
