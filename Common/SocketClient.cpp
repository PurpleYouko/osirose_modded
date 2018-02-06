/*
    Rose Online Server Emulator
    Copyright (C) 2006,2007 OSRose Team http://osroseon.to.md

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

    developed with Main erose/hrose source server + some change from the original eich source
*/
#include "sockets.h"
#include "config.h"

// Constructor
CClientSocket::CClientSocket( )
{
	PacketSize		= 6;		// Starting size
	PacketOffset	= 0;		// No bytes read, yet.
}

// Destructor
CClientSocket::~CClientSocket( )
{

}

// Receive this client's socket
bool CClientSocket::ReceiveData( )
{
	int   ReceivedBytes;
	short BytesToRead;

	// Calculate bytes to read to get the full packet
	BytesToRead = PacketSize - PacketOffset;
	//Log(MSG_DEBUG, "Packet received from Client");
	//Log(MSG_DEBUG, "Packet size %i", PacketSize );
	//Log(MSG_DEBUG, "Packet Offset %i", PacketOffset );
	//Log(MSG_DEBUG, "Bytes to read %i", BytesToRead );
	// This should never happen, but it is integrated:
	if ( BytesToRead > 0x400 - PacketOffset ) return false;
	if ( BytesToRead == 0 ) return false;

	// Receive data from client
	ReceivedBytes = recv( sock, (char*)&Buffer[ PacketOffset ], BytesToRead, 0 );

	if ( ReceivedBytes <= 0 ) return false;


    //print out packet to console
    //printf("Recv ");
    //for (int i = 0; i < BytesToRead; i++)
    //{
    //    printf("%02x ", Buffer[i]);
    //}
    //printf("\n");

	// Update pointer
	PacketOffset += ReceivedBytes;

	// If the packet is not complete, leave the function
	if ( ReceivedBytes != BytesToRead )
	{
	    Log(MSG_DEBUG, "Packet not complete. leaving the function" );
	    return true;
	}

	if ( PacketSize == 6 )
	{
		// We received the headerblock
#ifdef EXJAM
    CPacket* header = (CPacket*)&Buffer;
    PacketSize = header->Size;
    //PacketSize = DecryptBufferHeader( &CryptStatus, CryptTable, Buffer );
#else
    #ifndef USE124
            PacketSize = DecryptBufferHeader( &CryptStatus, CryptTable, Buffer );
    #else
            CPacket* header = (CPacket*)&Buffer;
            PacketSize = header->Size;
    #endif
#endif

		// Did we receive an incorrect buffer?
		if ( PacketSize < 6 )
		{
			Log(MSG_ERROR, "(SID:%i) Client sent incorrect blockheader.", sock );
			return false;
		}

		// Is the packet larger than just the header, then continue receiving
		if ( PacketSize > 6 )
		{
		    //Log(MSG_DEBUG, "Packet size is %i. Continue receiving", PacketSize);
		    return true;
		}
		//Log(MSG_DEBUG, "Guess Packet size must still be 6 if it got here %i", PacketSize );
	}

#ifdef EXJAM
    //cryptPacket( (char*)Buffer, this->ct);
    //Log(MSG_DEBUG, "not runing CryptPacket since it's not coming in encrypted anyway");
#else
    #ifndef USE124
        // We received the whole packet - Now we try to decrypt it
        if ( !DecryptBufferData( CryptTable, Buffer ) )
        {
            Log(MSG_ERROR, "(SID:%i) Client sent illegal block.", sock );
            return false;
        }
    #else
        cryptPacket( (char*)Buffer, this->ct);
    #endif
#endif

    CPacket* pak = (CPacket*)&Buffer;
    Log(MSG_DEBUG, "Received %04x containing Bytes %i", pak->Command, pak->Size );

    FILE *fh = fopen(  "log/inoutpackets.log", "a+" );
    if ( fh != NULL )
    {
        fprintf( fh, "(SID:%08u) IN  %04x: ", sock, pak->Command );
        for ( int i=0; i<pak->Size-6; ++i ) fprintf( fh, "%02x ", (unsigned char)pak->Buffer[i] );
        fprintf( fh, "\n" );
        fclose( fh );
    }

	// Handle actions for this packet
	if ( !GS->OnReceivePacket( this, pak ) )
	{
         //Log(MSG_ERROR, "onrecieve packet returned false");
         return false;
    }


	// Reset values for the next packet
	PacketSize   = 6;
	PacketOffset = 0;

    //Log(MSG_DEBUG, "Reached end of receivePackets" );
	return true;
}

// Send a packet to this client
void CClientSocket::SendPacket( CPacket *P )
{
	//first log it so we don't have to worry about encryption. set logfile to false to prevent logging
	Log(MSG_DEBUG, "Sending pak %04x containing %i bytes",P->Command, P->Size);
	bool LogFile = true;

	FILE *fh = fopen(  "log/inoutpackets.log", "a+" );
	if ( fh != NULL and LogFile)
	{
		fprintf( fh, "(SID:%08u) OUT %04x: ", sock, P->Command );
		for ( int i=0; i<P->Size-6; ++i ) fprintf( fh, "%02x ", (unsigned char)P->Buffer[i] );
		fprintf( fh, "\n" );
		fclose( fh );
	}


	// :WARNING: IF WE ADD A CRYPT FUNCTION HERE WE MUST COPY THE
	//             PACKET AND NOT USE THE ORIGINAL, IT WILL FUCK UP
	//             THE SENDTOALL FUNCTIONS

    unsigned char* Buffer = (unsigned char*)P;
	unsigned Size = P->Size;
#ifdef EXJAM
send( sock, (char*)Buffer, Size, 0 );
#else
    #ifndef USE124
        EncryptBuffer( CryptTable, Buffer );
    #endif
        send( sock, (char*)Buffer, Size, 0 );
#endif

    //output sent packet to the console
    //printf("Send ");
    //for (int i = 0; i < Size; i++)
    //{
    //    printf("%02x ", Buffer[i]);
    //}
    //printf("\n");

}

//-------------------------------------------------------------------------
// Send a packet to a client without encrypting the source packet
//-------------------------------------------------------------------------
void CClientSocket::SendPacketCpy( CPacket *P )
{
	CPacket NewPacket;

	memcpy( &NewPacket, P, sizeof( CPacket ) );
	SendPacket( &NewPacket );
}

// Handle client socket (threads)
PVOID ClientMainThread( PVOID ClientSocket )
{
    CClientSocket* thisplayer = (CClientSocket*) ClientSocket;
	fd_set fds;
    while(thisplayer->isActive)
    {
        FD_ZERO(&fds);
        FD_SET (thisplayer->sock, &fds);
        int Select = select( thisplayer->sock+1, &fds, NULL, NULL, NULL );
        if(Select == SOCKET_ERROR)
        {
            Log( MSG_ERROR,NULL,"Error in Select");
            thisplayer->isActive = false;
        }
        else
        {
            if(FD_ISSET( thisplayer->sock, &fds ))
            {
                if (thisplayer->isserver == true)
                {
                   //Log( MSG_INFO,"ISC PACKET");
                   thisplayer->ISCThread();
                }
                else
                if(!thisplayer->ReceiveData( ))
                {
                    thisplayer->isActive = false;
                }
            }
        }

    }
    thisplayer->GS->DisconnectClient( thisplayer );
    pthread_exit(NULL);
	return 0 ;
}

// -----------------------------------------------------------------------------------------
