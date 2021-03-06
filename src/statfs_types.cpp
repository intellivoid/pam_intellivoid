#include "statfs_types.h"

const std::map<uint32_t, filesystems_t> filesystems = 
{
    {0xadf5,     filesystems_t("adfs",                "ADFS_SUPER_MAGIC",            0xadf5,     false, false, false)},
    {0xADFF,     filesystems_t("affs",                "AFFS_SUPER_MAGIC",            0xADFF,     false, false, false)},
    {0x0187,     filesystems_t("autofs",              "AUTOFS_SUPER_MAGIC",          0x0187,     false, false, true )},
    {0x62646576, filesystems_t("bdevfs",              "BDEVFS_MAGIC",                0x62646576, false, false, false)},
    {0x42465331, filesystems_t("befs",                "BEFS_SUPER_MAGIC",            0x42465331, false, false, false)},
    {0x1BADFACE, filesystems_t("bfs",                 "BFS_MAGIC",                   0x1BADFACE, false, false, false)},
    {0x42494e4d, filesystems_t("binfmt_misc",         "BINFMTFS_MAGIC",              0x42494e4d, false, false, true )},
    {0xcafe4a11, filesystems_t("bpf",                 "BPF_FS_MAGIC",                0xcafe4a11, false, false, true )},
    {0x9123683E, filesystems_t("btrfs",               "BTRFS_SUPER_MAGIC",           0x9123683E, false, true,  false)},
    {0x27e0eb,   filesystems_t("cgroupfs",            "CGROUP_SUPER_MAGIC",          0x27e0eb,   false, false, true )},
    {0x63677270, filesystems_t("",                    "CGROUP2_SUPER_MAGIC",         0x63677270, false, false, true )},
    {0xFF534D42, filesystems_t("cifs",                "CIFS_MAGIC_NUMBER",           0xFF534D42, true,  false, false)},
    {0x73757245, filesystems_t("coda",                "CODA_SUPER_MAGIC",            0x73757245, false, false, false)},
    {0x012FF7B7, filesystems_t("coh",                 "COH_SUPER_MAGIC",             0x012FF7B7, false, false, false)},
    {0x62656570, filesystems_t("configfs",            "CONFIGFS_MAGIC",              0x62656570, false, false, true )},
    {0x28cd3d45, filesystems_t("cramfs",              "CRAMFS_MAGIC",                0x28cd3d45, false, false, false)},
    {0x64626720, filesystems_t("debugfs",             "DEBUGFS_MAGIC",               0x64626720, false, false, true )},
    {0x1373,     filesystems_t("devfs",               "DEVFS_SUPER_MAGIC",           0x1373,     false, false, false)},
    {0x1cd1,     filesystems_t("devpts",              "DEVPTS_SUPER_MAGIC",          0x1cd1,     false, false, false)},
    {0xde5e81e4, filesystems_t("efivarsfs",           "EFIVARFS_MAGIC",              0xde5e81e4, false, false, false)},
    {0x00414A53, filesystems_t("efs",                 "EFS_SUPER_MAGIC",             0x00414A53, false, false, false)},
    {0x137D,     filesystems_t("ext",                 "EXT_SUPER_MAGIC",             0x137D,     false, true,  false)},
    {0xEF51,     filesystems_t("ext2",                "EXT2_OLD_SUPER_MAGIC",        0xEF51,     false, true,  false)},
    {0xEF53,     filesystems_t("ext2/ext3",           "EXT2_SUPER_MAGIC",            0xEF53,     false, true,  false)},
    {0xEF53,     filesystems_t("ext3",                "EXT3_SUPER_MAGIC",            0xEF53,     false, true,  false)},
    {0xEF53,     filesystems_t("ext4",                "EXT4_SUPER_MAGIC",            0xEF53,     false, true,  false)},
    {0x65735546, filesystems_t("fusefs",              "FUSE_SUPER_MAGIC",            0x65735546, false, false, false)},
    {0xBAD1DEA,  filesystems_t("futexfs",             "FUTEXFS_SUPER_MAGIC",         0xBAD1DEA,  false, false, false)},
    {0x4244,     filesystems_t("hfs",                 "HFS_SUPER_MAGIC",             0x4244,     false, false, false)},
    {0x482b,     filesystems_t("hfsplus",             "HFSPLUS_SUPER_MAGIC",         0x482b,     false, false, false)},
    {0x00c0ffee, filesystems_t("hostfs",              "HOSTFS_SUPER_MAGIC",          0x00c0ffee, false, false, false)},
    {0xF995E849, filesystems_t("hpfs",                "HPFS_SUPER_MAGIC",            0xF995E849, false, true,  false)},
    {0x958458f6, filesystems_t("hugetlbfs",           "HUGETLBFS_MAGIC",             0x958458f6, false, false, true )},
    {0x9660,     filesystems_t("isofs",               "ISOFS_SUPER_MAGIC",           0x9660,     false, false, false)},
    {0x72b6,     filesystems_t("jffs2",               "JFFS2_SUPER_MAGIC",           0x72b6,     false, false, false)},
    {0x3153464a, filesystems_t("jfs",                 "JFS_SUPER_MAGIC",             0x3153464a, false, false, false)},
    {0x137F,     filesystems_t("minix",               "MINIX_SUPER_MAGIC",           0x137F,     false, false, false)},
    {0x138F,     filesystems_t("minix (30 char.)",    "MINIX_SUPER_MAGIC2",          0x138F,     false, false, false)},
    {0x2468,     filesystems_t("minix v2",            "MINIX2_SUPER_MAGIC",          0x2468,     false, false, false)},
    {0x2478,     filesystems_t("minix v2 (30 char.)", "MINIX2_SUPER_MAGIC2",         0x2478,     false, false, false)},
    {0x4d5a,     filesystems_t("minix3",              "MINIX3_SUPER_MAGIC",          0x4d5a,     false, false, false)},
    {0x19800202, filesystems_t("mqueue",              "MQUEUE_MAGIC",                0x19800202, false, false, true )},
    {0x4d44,     filesystems_t("msdos",               "MSDOS_SUPER_MAGIC",           0x4d44,     false, true,  false)},
    {0x564c,     filesystems_t("novell",              "NCP_SUPER_MAGIC",             0x564c,     false, false, false)},
    {0x6969,     filesystems_t("nfs",                 "NFS_SUPER_MAGIC",             0x6969,     true,  false, false)},
    {0x3434,     filesystems_t("nilfs",               "NILFS_SUPER_MAGIC",           0x3434,     false, false, false)},
    {0x5346544e, filesystems_t("ntfs",                "NTFS_SB_MAGIC",               0x5346544e, false, true,  false)},
    {0x7461636f, filesystems_t("ocfs2",               "OCFS2_SUPER_MAGIC",           0x7461636f, false, false, false)},
    {0x9fa1,     filesystems_t("openprom",            "OPENPROM_SUPER_MAGIC",        0x9fa1,     false, false, false)},
    {0x50495045, filesystems_t("pipefs",              "PIPEFS_MAGIC",                0x50495045, false, false, false)},
    {0x9fa0,     filesystems_t("proc",                "PROC_SUPER_MAGIC",            0x9fa0,     false, false, true )},
    {0x6165676C, filesystems_t("pstorefs",            "PSTOREFS_MAGIC",              0x6165676C, false, false, true )},
    {0x002f,     filesystems_t("qnx4",                "QNX4_SUPER_MAGIC",            0x002f,     false, false, false)},
    {0x68191122, filesystems_t("qnx6",                "QNX6_SUPER_MAGIC",            0x68191122, false, false, false)},
    {0x858458f6, filesystems_t("ramfs",               "RAMFS_MAGIC",                 0x858458f6, false, false, false)},
    {0x52654973, filesystems_t("reiserfs",            "REISERFS_SUPER_MAGIC",        0x52654973, false, true,  false)},
    {0x7275,     filesystems_t("romfs",               "ROMFS_MAGIC",                 0x7275,     false, false, false)},
    {0xf97cff8c, filesystems_t("selinux",             "SELINUX_MAGIC",               0xf97cff8c, false, false, false)},
    {0x43415d53, filesystems_t("smackfs",             "SMACK_MAGIC",                 0x43415d53, false, false, false)},
    {0x517B,     filesystems_t("smb",                 "SMB_SUPER_MAGIC",             0x517B,     true,  false, false)},
    {0xfe534d42, filesystems_t("smb2",                "SMB2_MAGIC_NUMBER",           0xfe534d42, true,  false, false)},
    {0x534F434B, filesystems_t("sockfs",              "SOCKFS_MAGIC",                0x534F434B, false, false, false)},
    {0x73717368, filesystems_t("squashfs",            "SQUASHFS_MAGIC",              0x73717368, false, false, false)},
    {0x62656572, filesystems_t("sysfs",               "SYSFS_MAGIC",                 0x62656572, false, false, true )},
    {0x012FF7B6, filesystems_t("sysv2",               "SYSV2_SUPER_MAGIC",           0x012FF7B6, false, false, false)},
    {0x012FF7B5, filesystems_t("sysv4",               "SYSV4_SUPER_MAGIC",           0x012FF7B5, false, false, false)},
    {0x01021994, filesystems_t("tmpfs",               "TMPFS_MAGIC",                 0x01021994, false, false, true )},
    {0x74726163, filesystems_t("tracefs",             "TRACEFS_MAGIC",               0x74726163, false, false, true )},
    {0x15013346, filesystems_t("udf",                 "UDF_SUPER_MAGIC",             0x15013346, false, true,  false)},
    {0x00011954, filesystems_t("ufs",                 "UFS_MAGIC",                   0x00011954, false, false, false)},
    {0x9fa2,     filesystems_t("usbdevfs",            "USBDEVICE_SUPER_MAGIC",       0x9fa2,     false, false, false)},
    {0x01021997, filesystems_t("v9fs",                "V9FS_MAGIC",                  0x01021997, false, false, false)},
    {0xa501FCF5, filesystems_t("vxfs",                "VXFS_SUPER_MAGIC",            0xa501FCF5, false, false, false)},
    {0xabba1974, filesystems_t("xenfs",               "XENFS_SUPER_MAGIC",           0xabba1974, false, false, false)},
    {0x012FF7B4, filesystems_t("xenix",               "XENIX_SUPER_MAGIC",           0x012FF7B4, false, false, false)},
    {0x58465342, filesystems_t("xfs",                 "XFS_SUPER_MAGIC",             0x58465342, false, true,  false)},
    {0x012FD16D, filesystems_t("xia",                 "_XIAFS_SUPER_MAGIC",          0x012FD16D, false, false, false)},
    {0x5346414F, filesystems_t("afs",                 "AFS_SUPER_MAGIC",             0x5346414F, false, true,  false)},
    {0x61756673, filesystems_t("aufs",                "AUFS_SUPER_MAGIC",            0x61756673, false, false, false)},
    {0x09041934, filesystems_t("anon-inode FS",       "ANON_INODE_FS_SUPER_MAGIC",   0x09041934, false, false, false)},
    {0x00C36400, filesystems_t("ceph",                "CEPH_SUPER_MAGIC",            0x00C36400, false, false, false)},
    {0xF15F,     filesystems_t("ecryptfs",            "ECRYPTFS_SUPER_MAGIC",        0xF15F,     false, false, false)},
    {0x4006,     filesystems_t("fat",                 "FAT_SUPER_MAGIC",             0x4006,     false, true,  false)},
    {0x19830326, filesystems_t("fhgfs",               "FHGFS_SUPER_MAGIC",           0x19830326, false, false, false)},
    {0x65735546, filesystems_t("fuseblk",             "FUSEBLK_SUPER_MAGIC",         0x65735546, false, false, false)},
    {0x65735543, filesystems_t("fusectl",             "FUSECTL_SUPER_MAGIC",         0x65735543, false, false, true )},
    {0x1161970,  filesystems_t("gfs/gfs2",            "GFS_SUPER_MAGIC",             0x1161970,  false, false, false)},
    {0x47504653, filesystems_t("gpfs",                "GPFS_SUPER_MAGIC",            0x47504653, false, false, false)},
    {0x11307854, filesystems_t("inodefs",             "MTD_INODE_FS_SUPER_MAGIC",    0x11307854, false, false, false)},
    {0x2BAD1DEA, filesystems_t("inotifyfs",           "INOTIFYFS_SUPER_MAGIC",       0x2BAD1DEA, false, false, false)},
    {0x4004,     filesystems_t("isofs",               "ISOFS_R_WIN_SUPER_MAGIC",     0x4004,     false, false, false)},
    {0x4000,     filesystems_t("isofs",               "ISOFS_WIN_SUPER_MAGIC",       0x4000,     false, false, false)},
    {0x07C0,     filesystems_t("jffs",                "JFFS_SUPER_MAGIC",            0x07C0,     false, false, false)},
    {0x6B414653, filesystems_t("k-afs",               "KAFS_SUPER_MAGIC",            0x6B414653, false, false, false)},
    {0x0BD00BD0, filesystems_t("lustre",              "LUSTRE_SUPER_MAGIC",          0x0BD00BD0, false, false, false)},
    {0x6E667364, filesystems_t("nfsd",                "NFSD_SUPER_MAGIC",            0x6E667364, false, false, false)},
    {0xAAD7AAEA, filesystems_t("panfs",               "PANFS_SUPER_MAGIC",           0xAAD7AAEA, false, false, false)},
    {0x67596969, filesystems_t("rpc_pipefs",          "RPC_PIPEFS_SUPER_MAGIC",      0x67596969, false, false, false)},
    {0x73636673, filesystems_t("securityfs",          "SECURITYFS_SUPER_MAGIC",      0x73636673, false, false, true )},
    {0x54190100, filesystems_t("ufs",                 "UFS_BYTESWAPPED_SUPER_MAGIC", 0x54190100, false, false, false)},
    {0xBACBACBC, filesystems_t("vmhgfs",              "VMHGFS_SUPER_MAGIC",          0xBACBACBC, false, false, false)},
    {0x565A4653, filesystems_t("vzfs",                "VZFS_SUPER_MAGIC",            0x565A4653, false, false, false)},
    {0x2FC12FC1, filesystems_t("zfs",                 "ZFS_SUPER_MAGIC",             0x2FC12FC1, false, true,  false)}
};