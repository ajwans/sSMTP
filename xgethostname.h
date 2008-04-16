/* Copyright (c) 2001 Neal H Walfield <neal@cs.uml.edu>.
   
   This file is placed into the public domain.  Its distribution
   is unlimited.

   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
   IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
   IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* NAME

	xgethostname - get the host name.

   SYNOPSIS

   	char *xgethostname (void);

   DESCRIPTION

	The xhostname function is intended to replace gethostname(2), a
	function used to access the host name.  The old interface is
	inflexable given that it assumes the existance of the
	MAXHOSTNAMELEN macro, which neither POSIX nor the proposed
	Single Unix Specification version 3 guarantee to be defined.

   RETURN VALUE

	On success, a malloced, null terminated (possibly truncated)
	string containing the host name is returned.  On failure,
	NULL is returned and errno is set.
 */

#ifndef XGETHOSTNAME
#define XGETHOSTNAME

char * xgethostname (void);

#endif /* XGETHOSTNAME */

