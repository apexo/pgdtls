HDR = """
typedef %(IN_PORT_T)s in_port_t;
typedef uint32_t socklen_t;

typedef struct iovec
{
	void *iov_base;			/* Pointer to data.  */
	size_t iov_len;			/* Length of data.  */
};

typedef struct sockaddr
{
	unsigned short int sa_family;	/* Common data: address family and length.  */
	char sa_data[14];		/* Address data.  */
};

typedef struct sockaddr_storage
{
	unsigned short int ss_family;	/* Address family, etc.  */
	%(SS_ALIGNTYPE)s __ss_align;	/* Force desired alignment.  */
	char __ss_padding[%(SS_PADSIZE)d];
};

typedef uint32_t in_addr_t;
typedef struct in_addr
{
	in_addr_t s_addr;
};


typedef struct in6_addr
{
	union
	{
		uint8_t	__u6_addr8[16];
		uint16_t __u6_addr16[8];
		uint32_t __u6_addr32[4];
	} __in6_u;
};

typedef struct sockaddr_in
{
	unsigned short int sin_family;
	in_port_t sin_port;		/* Port number.  */
	struct in_addr sin_addr;	/* Internet address.  */

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sin_zero[%(SIN_PADSIZE)d];
};

/* Ditto, for IPv6.  */
typedef struct sockaddr_in6
{
	unsigned short int sin6_family;
	in_port_t sin6_port;		/* Transport layer port # */
	uint32_t sin6_flowinfo;		/* IPv6 flow information */
	struct in6_addr sin6_addr;	/* IPv6 address */
	uint32_t sin6_scope_id;		/* IPv6 scope-id */
};

typedef struct msghdr
{
	void *msg_name;		/* Address to send to/receive from.  */
	socklen_t msg_namelen;	/* Length of address data.  */

	struct iovec *msg_iov;	/* Vector of data to send/receive into.  */
	size_t msg_iovlen;	/* Number of elements in the vector.  */

	void *msg_control;	/* Ancillary data (eg BSD filedesc passing). */
	size_t msg_controllen;	/* Ancillary data buffer length.
					!! The type should be socklen_t but the
					definition of the kernel is incompatible
					with this.  */
	int msg_flags;		/* Flags on received message.  */
};

typedef struct mmsghdr
{
	struct msghdr msg_hdr;	/* Message header */
	unsigned int msg_len;	/* Number of received bytes for header */
};


ssize_t sendmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

/* FIXME: this is not very portable */
typedef struct timespec
{
	int64_t tv_sec;		/* Seconds.  */
	int64_t tv_nsec;	/* Nanoseconds.  */
};

int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout);

"""

def get_cdef(ffi):
	SS_ALIGNTYPE = "unsigned long int"
	SS_PADSIZE = 128 - 2 * ffi.sizeof(SS_ALIGNTYPE)
	IN_PORT_T = "uint16_t"
	SIN_PADSIZE = 16 - ffi.sizeof(IN_PORT_T) - ffi.sizeof("unsigned short int") - 4

	return HDR % {
		"SS_ALIGNTYPE": SS_ALIGNTYPE,
		"SS_PADSIZE": SS_PADSIZE,
		"IN_PORT_T": IN_PORT_T,
		"SIN_PADSIZE": SIN_PADSIZE,
	}
