/*==============================================================================
MIT License

Copyright (c) 2024 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup varmsg Variable Message Generator
 * @brief Construct and send variable messages to an output destination
 * @{
 */

/*============================================================================*/
/*!
@file varmsg.c

    Variable Message Generator

    The varmsg service generates variable messages and sends them
    to a specified output whenever the send conditions are met.

    The message generate can build multiple messages, each one governed
    by an input configuration file, which is loaded and processed when
    the services is started.

    The message generator builds its messages based on a local VarCache.

    The VarCache can be built manually, or from a variable query.

    The output type is configurable, and can be one of:

    - standard output (used for testing)
    - output file
    - message queue

    Each configuration may have a variable prefix associated with it,
    and exposes status and control variables to change the behavior at
    runtime.  For example if the variable prefix for a variable message
    is /msg1, then the following variables will be available:

    /msg1/txcount - counts the number of generations/transmissions
    /msg1/errcount - counts the number of errors during generation/transmission
    /msg1/enable - enables or disables sending the data
    /msg1/rescan - forces a re-generation of variable sets

    Each configuration is configured using a JSON configuration file
    loaded from the configuration directory on startup.

    It has the following settings:

    prefix : message prefix for control/status variables
    interval : generation interval (seconds) (optional)
    triggers : query or variable list (optional)
    outputset : query or variable list
    outputtype : one of stdout, file, mqueue
    header : location of header template file

    An example configuration is shown below:

    {
        "enabled" : true,
        "output_type" : "mqueue",
        "output" : "/splunk",
        "prefix" : "/varmsg/msg1/",
        "header" : "/usr/share/headers/header1",
        "interval" : 60,
        "trigger" : {
            "tags" : "test",
            "flags" : "volatile"
        },
        "vars" : {
            "tags" : "test"
        }
    }

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dirent.h>
#include <tjson/json.h>
#include <varserver/vartemplate.h>
#include <varserver/varserver.h>
#include <varserver/varcache.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! The MsgOutputType specifies the type of output target to write to */
typedef enum _msgOutputType
{
    /*! output disabled */
    VARMSG_OUTPUT_DISABLED = 0,

    /*! output to stdout */
    VARMSG_OUTPUT_STDOUT,

    /*! output to message queue */
    VARMSG_OUTPUT_MQUEUE,

    /*! output to file */
    VARMSG_OUTPUT_FILE

} MsgOutputType;

/*! Variable Message state */
typedef struct _varMsgState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose flag */
    bool verbose;

    /*! name of the configuration directory */
    char *pConfigDir;

    /*! name of the configuration file */
    char *pConfigFile;

    /*! the number of variable messages this service is managing */
    uint32_t numMsgs;

} VarMsgState;

/*! The VarMsgConfig object manages a single variable message
    to be */
typedef struct _varMsgConfig
{
    /*! flag to indicate if the message is enabled (true) or disabled (false) */
    bool enabled;

    /*! configuration name */
    char *configName;

    /*! variable message configuration prefix */
    char *prefix;

    /*! time interval in seconds */
    uint32_t interval;

    /*! transmission counter */
    uint32_t txCount;

    /*! error counter */
    uint32_t errCount;

    /* query for trigger variables */
    VarQuery triggerQuery;

    /* query for variables in message body */
    VarQuery varSet;

    /*! cache of variables to trigger on */
    VarCache *pTriggerCache;

    /*! cache of variables to put in message body */
    VarCache *pVarCache;

    /*! pointer to the next variable message */
    struct _varMsgConfig *pNext;
} VarMsgConfig;

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! pointer to variable message list */
static VarMsgConfig *pVarMsgs = NULL;

/*! list of output types.  These must be in the same order
    as the MsgOutputType enumeration */
static const char const *outputTypes[] = {
    "disabled",
    "stdout",
    "mqueue",
    "file",
    NULL
};

/*! handle to the variable server */
VARSERVER_HANDLE hVarServer = NULL;

/*==============================================================================
        Private function declarations
==============================================================================*/

void main(int argc, char **argv);
static int ProcessOptions( int argC, char *argV[], VarMsgState *pState );
static void usage( char *cmdname );
static int ProcessConfigDir( VarMsgState *pState, char *pDirname );
static int ProcessConfigFile( VarMsgState *pState, char *filename );
static MsgOutputType ParseOutputType( char *outputtype );
static int ProcessQuery( JObject *config, VarQuery *query );
static int ProcessVarList( JArray *pVarList, VarCache **ppVarCache );
static int AddToCache( JNode *pNode, void *arg );

/*==============================================================================
        Private function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the VarMsg application

    The main function starts the VarMsg application

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
void main(int argc, char **argv)
{
    VarMsgState state;
    int result = EINVAL;

    /* clear the variable message state object */
    memset( &state, 0, sizeof( state ) );

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* open a handle to the variable server */
    hVarServer = VARSERVER_Open();
    if( hVarServer != NULL )
    {
        state.hVarServer = hVarServer;

        if ( state.pConfigDir != NULL )
        {
            result = ProcessConfigDir( &state, state.pConfigDir ) ;
        }

        if ( state.pConfigFile != NULL )
        {
              /* Process the configuration file */
            result = ProcessConfigFile( &state, state.pConfigFile );

        }

        if ( state.numMsgs == 0 )
        {
            fprintf( stderr, "At least one configuration must be specified\n");
            usage( argv[0] );
        }

        /* close the handle to the variable server */
        VARSERVER_Close( hVarServer );
    }
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message
    to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] [-f config file] [-d config dir]\n"
                " [-h] : display this help\n"
                " [-v] : verbose output\n"
                " [-f] : specify the configuration file for a single message\n"
                " [-d] : specify a configuration directory with many configs\n",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the ExecVarState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the variable message generator state object

    @return 0

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], VarMsgState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "hvf:d:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'v':
                    pState->verbose = true;
                    break;

                case 'h':
                    usage( argV[0] );
                    break;

                case 'f':
                    pState->pConfigFile = strdup(optarg);
                    break;

                case 'd':
                    pState->pConfigDir = strdup(optarg);
                    break;

                default:
                    break;

            }
        }
    }

    return 0;
}

/*============================================================================*/
/*  ProcessConfigDir                                                          */
/*!
    Process a configuration directory containing one or more configuration files

    The ProcessConfigDir processes the specified configuration directory
    by iterating through and processing each configuration file.

    @param[in]
        pState
            pointer to the Variable Message Generator state containing the
            name of the configuration directory

    @param[in]
        pDirname
            pointer to the configuration directory name

    @retval EINVAL invalid arguments
    @retval EOK the directory was processed successfully

============================================================================*/
static int ProcessConfigDir( VarMsgState *pState, char *pDirname )
{
    int result = EINVAL;
    DIR *configdir = NULL;
    struct dirent *entry;

    if ( ( pState != NULL ) &&
         ( pDirname != NULL ) )
    {
        result = EOK;

        if( pState->verbose == true )
        {
            fprintf( stdout, "VARMSG: Processing directory: %s\n", pDirname );
        }

        configdir = opendir( pDirname );
        if( configdir != NULL )
        {
            while( entry = readdir( configdir ) )
            {
                /* process configuration file */
                ProcessConfigFile( pState, entry->d_name );
            }

            closedir( configdir );
        }
    }

    return result;
}

/*==========================================================================*/
/*  ProcessConfigFile                                                       */
/*!
    Process the specified configuration file

    The ProcessConfigFile function processes a configuration file
    consisting of lines of directives and variable assignments.


    @param[in]
        pState
            pointer to the Variable Message Generator state

    @param[in]
        filename
            pointer to the name of the file to load

    @retval EINVAL invalid arguments
    @retval EOK file processed ok
    @retval other error as returned by ProcessConfigData

==============================================================================*/
static int ProcessConfigFile( VarMsgState *pState, char *filename )
{
    int result = EINVAL;
    char *pFileName = NULL;
    JNode *config;
    VarMsgConfig *pMsgConfig;
    JNode *node;

    if ( filename != NULL )
    {
        pFileName = strdup( filename );
    }

    if ( ( pState != NULL ) &&
         ( pFileName != NULL ) )
    {
        if ( pState->verbose == true )
        {
            printf("ProcessConfigFile: %s\n", pFileName );
        }

        /* parse the JSON config file */
        config = JSON_Process( pFileName );

        /* allocate a VarMsgConfig object */
        pMsgConfig = calloc( 1, sizeof( VarMsgConfig ) );
        if ( pMsgConfig != NULL )
        {
            /* set the configuration name */
            pMsgConfig->configName = pFileName;

            /* check enabled flag */
            pMsgConfig->enabled = JSON_GetBool( config, "enabled" );

            /* get variable prefix */
            pMsgConfig->prefix = JSON_GetStr( config, "prefix" );

            /* get processing interval */
            JSON_GetNum( config, "interval", &pMsgConfig->interval );

            /* process trigger variables */
            node = JSON_Find( config, "trigger" );
            if ( node != NULL )
            {
                if ( node->type == JSON_OBJECT )
                {
                    /* process a variable query */
                    result = ProcessQuery( (JObject *)node,
                                           &pMsgConfig->triggerQuery );
                }
                else if ( node->type == JSON_ARRAY )
                {
                    /* process a variable list */
                    result = ProcessVarList( (JArray *)node,
                                             &(pMsgConfig->pTriggerCache) );
                }
            }

            /* process message body variables */
            node = JSON_Find( config, "vars" );
            if ( node != NULL )
            {
                if ( node->type == JSON_OBJECT )
                {
                    /* process a variable query */
                    result = ProcessQuery( (JObject *)node,
                                           &pMsgConfig->varSet );
                }
                else if ( node->type == JSON_ARRAY )
                {
                    /* process a variable list */
                    result = ProcessVarList( (JArray *)node,
                                             &(pMsgConfig->pVarCache) );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ParseOutputType                                                           */
/*!
    Parse the output type string

    The ParseOutputType function processes the specified output type string
    and converts it into a MsgOutputType enum.  If an invalid string
    is specified, the output type will be silently set to VARMSG_OUTPUT_DISABLED

    @param[in]
        outputtype
            pointer to a NUL terminated output type string

    @retval the corresponding output type enumeration value.

==============================================================================*/
static MsgOutputType ParseOutputType( char *outputtype )
{
    int i = 0;
    int n = sizeof(outputTypes)/sizeof(outputTypes[0]);
    MsgOutputType outputType = VARMSG_OUTPUT_DISABLED;
    const char *type;

    if ( outputtype != NULL )
    {
        /* get the first output type */
        type = outputTypes[i];
        while ( type != NULL )
        {
            if ( strcmp(type, outputtype ) == 0 )
            {
                outputType = (MsgOutputType)i;
                break;
            }

            type = outputTypes[++i];
        }
    }

    return outputType;
}

/*============================================================================*/
/*  ProcessQuery                                                              */
/*!
    Process a Variable Query object

    The ProcessQuery function processes a variable query JSON object
    which specifies the variable search parameters used to generate
    a list of variables to process.

    A JSON variable query can have the following attributes:

    instanceID - instance identifier
    match - partial name string match
    flags - flags match ( comma separated list of flags to search for )
    tags - tags match ( comma separated list of tags to search for )

    @param[in]
        config
            pointer to a JSON Object containing variable query
            parameters

    @param[in,out]
        query
            pointer to a Variable Query object to populate

    @retval EOK the variable query was successfully processed
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessQuery( JObject *config, VarQuery *query )
{
    int result = EINVAL;
    JNode *pNode;
    char *tags;
    char *match;
    char *flags;
    size_t len;

    if ( ( config != NULL ) &&
         ( config->node.type == JSON_OBJECT ) &&
         ( query != NULL ) )
    {
        query->type = 0;

        /* get a pointer to the JSON node */
        pNode = &(config->node);

        /* see if we are doing a tags search */
        tags = JSON_GetStr( pNode, "tags" );
        if ( tags != NULL )
        {
            len = strlen( tags );
            if ( len < MAX_TAGSPEC_LEN )
            {
                strcpy( query->tagspec, tags );
                query->type |= QUERY_TAGS;
            }
            else
            {
                result = E2BIG;
            }
        }

        /* see if we are doing a match search */
        match = JSON_GetStr( pNode, "match" );
        if ( match != NULL )
        {
            query->match = strdup( match );
            if ( query->match != NULL )
            {
                query->type |= QUERY_MATCH;
            }
            else
            {
                result = ENOMEM;
            }
        }

        /* see if we are doing a flags search */
        flags = JSON_GetStr( pNode, "flags" );
        if ( flags != NULL )
        {
            /* convert flags string list to flags bitmap */
            if ( VARSERVER_StrToFlags( flags, &query->flags ) == EOK )
            {
                query->type |= QUERY_FLAGS;
            }
            else
            {
                result = ENOTSUP;
            }
        }

        /* see if we are doing an instance identifier search */
        if ( JSON_GetNum( pNode, "instanceID", &query->instanceID ) == EOK )
        {
            query->type |= QUERY_INSTANCEID;
        }
        else
        {
            result = ENOTSUP;
        }

        if ( ( result == EOK ) &&
             ( query->type == 0 ) )
        {
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessVarList                                                            */
/*!
    Process a JSON array of variables and build a VarCache list

    The ProcessVarList function iterates through the variable name
    array (array of strings), and adds each variable to a variable
    cache.  The variable cache is created and a pointer to it
    is returned via the ppVarCache argument.

    @param[in]
        pVarList
            pointer to a JSON Array containing a list of variable
            names.

    @param[in,out]
        ppVarCache
            pointer to a pointer to a variable cache

    @retval EOK the variable was added to the VarCache
    @retval ENOTSUP the type of object in the array is not a string
    @retval ENOENT the variable was not found
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessVarList( JArray *pVarList, VarCache **ppVarCache )
{
    int result = EINVAL;
    VarCache *pVarCache;
    int n;
    int i;
    JNode *pNode;

    if ( ( pVarList != NULL ) &&
         ( pVarList->node.type == JSON_ARRAY ) &&
         ( ppVarCache != NULL ) )
    {
        pVarCache = *ppVarCache;

        if ( pVarCache == NULL )
        {
            /* count the number of items in the array */
            n = JSON_GetArraySize( pVarList );
            if ( n > 0 )
            {
                /* build a VarCache of the same size */
                result = VARCACHE_Init( ppVarCache, n, 10 );
                if ( result == EOK )
                {
                    /* iterate through the variable list and build
                       the VarCache */
                    result = JSON_Iterate( pVarList,
                                           AddToCache,
                                           (void *)pVarCache );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  AddToCache                                                                */
/*!
    Add variable name from a JArray to the variable cache

    The AddToCache function is a callback function for the JSON_Iterate
    function used to add a variable name string from a JSON array to
    a VarCache list.

    @param[in]
        pNode
            pointer to the item in the JSON Array.  The type of this item
            is expected to be a string value.  If it is not, the function
            will fail with an ENOTSUP error

    @param[in]
        arg
            opaque argument pointer which points to a VarCache object.

    @retval EOK the variable was added to the VarCache
    @retval ENOTSUP the type of object in the array is not a string
    @retval ENOENT the variable was not found
    @retval EINVAL invalid arguments

==============================================================================*/
static int AddToCache( JNode *pNode, void *arg )
{
    int result = EINVAL;
    VarCache *pVarCache = (VarCache *)arg;
    JVar *pVar = (JVar *)pNode;
    VAR_HANDLE hVar;

    if ( ( pNode != NULL ) &&
         ( pNode->type == JSON_VAR ) &&
         ( pVarCache != NULL ) )
    {
        /* only strings are supported */
        result = ENOTSUP;
        if ( pVar->var.type == JVARTYPE_STR )
        {
            /* look for a variable given its name */
            hVar = VAR_FindByName( hVarServer, pVar->var.val.str );
            if ( hVar != VAR_INVALID )
            {
                /* add the variable to the cache */
                result = VARCACHE_Add( pVarCache, hVar );
            }
            else
            {
                /* variable not found */
                result = ENOENT;
            }
        }
    }

    return result;
}

/*! @}
 * end of varmsg group */
