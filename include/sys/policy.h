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
\*****************************************************************************/
#include <sys/types.h>
#include "cred.h"
#include "vnode.h"
#ifndef _SPL_POLICY_H
#define _SPL_POLICY_H

#define	secpolicy_fs_unmount(c,vfs)			(0)
//#define	secpolicy_nfs(c)				(0)
//#define	secpolicy_sys_config(c,co)			(0)
//#define	secpolicy_zfs(c)				(0)
//#define	secpolicy_zinject(c)				(0)
//#define	secpolicy_vnode_setids_setgids(c,id)		(0)
//#define	secpolicy_vnode_setid_retain(c, sr)		(0)
//#define	secpolicy_setid_clear(v, c)			(0)
//#define	secpolicy_vnode_any_access(c,vp,o)		(0)
//#define	secpolicy_vnode_access2(c,cp,o,m1,m2)		(0)
//#define	secpolicy_vnode_chown(c,o)			(0)
//#define	secpolicy_vnode_setdac(c,o)			(0)
//#define	secpolicy_vnode_remove(c)			(0)
//#define	secpolicy_vnode_setattr(c,v,a,o,f,func,n)	(0)
#define	secpolicy_xvattr(x, o, c, t)			(0)
//#define	secpolicy_vnode_stky_modify(c)			(0)
//#define	secpolicy_setid_setsticky_clear(v,a,o,c)	(0)
//#define	secpolicy_basic_link(c)				(0)

boolean_t secpolicy_sys_config(cred_t* c,boolean_t checkonly);
boolean_t secpolicy_nfs(cred_t* c);
boolean_t secpolicy_zfs(cred_t* c);
boolean_t secpolicy_zinject(cred_t* c);
boolean_t secpolicy_vnode_setids_setgids(cred_t* c,gid_t gid);
boolean_t secpolicy_vnode_setid_retain(cred_t* c,boolean_t is_setuid_root);
boolean_t secpolicy_setid_clear(vattr_t* v,cred_t* c);
boolean_t secpolicy_vnode_any_access(cred_t* c ,struct inode* ip,uid_t owner);
boolean_t secpolicy_vnode_access2(cred_t* c,struct inode* ip,uid_t owner,mode_t mode1,mode_t mode2);
boolean_t secpolicy_vnode_chown(cred_t* c,uid_t owner);
boolean_t secpolicy_vnode_setdac(cred_t* c,uid_t owner);
boolean_t secpolicy_vnode_remove(cred_t* c);
boolean_t secpolicy_vnode_setattr(cred_t* c, struct inode* ip,vattr_t* vap,vattr_t* oldvap,int flags,int (*fp)(void *, int, cred_t *),void* znode); //znode_t is defined in zfs not in spl
//boolean_t secpolicy_xvattr(void* [ should be xvattr_t*, but it is defined in zfs not in spl ] xv,uid_t owner,cred_t* cred,mode_t mode);
boolean_t secpolicy_vnode_stky_modify(cred_t* c);
boolean_t secpolicy_setid_setsticky_clear(struct inode* ip,vattr_t* attr,vattr_t* oldattr,cred_t* c);
boolean_t secpolicy_basic_link(cred_t* c);
boolean_t secpolicy_vnode_create_gid(cred_t* c); //previously not needed


#endif /* SPL_POLICY_H */
