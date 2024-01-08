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
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <dirent.h>
#include <tjson/json.h>
#include <varserver/vartemplate.h>
#include <varserver/varserver.h>
#include <varserver/varcache.h>
#include <varserver/varquery.h>
#include <varserver/varfp.h>

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
    int interval;

    /*! countdown timer starts at "interval" and counts down to zero */
    uint32_t t;

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

    /*! Variable Output stream */
    VarFP *pVarFP;

    /*! Variable output file descriptor */
    int varFd;

    /*! number of variables output for the current render */
    size_t outputCount;

    /*! output stream for current render */
    int fd;

    /*! pointer to a list of Variable Message Configurations managed
        by this instance */
    VarMsgConfig *pMessageConfigs;

} VarMsgState;


/*! Initial variable cache size */
#define CACHE_SIZE_INITIAL          ( 50 )

/*! Amount that the variable cache will grow by if it is full */
#define CACHE_SIZE_GROW_BY          ( 50 )

/*! size for the variable rendering output buffer */
#define VARFP_SIZE                  ( 256 * 1024 )

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! Variable Message Manager State */
static VarMsgState state;

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

int main(int argc, char **argv);
static int ProcessOptions( int argC, char *argV[], VarMsgState *pState );
static void usage( char *cmdname );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );
static void SetupTerminationHandler( void );
static int SetupVarFP( VarMsgState *pState );
static int ProcessConfigDir( VarMsgState *pState, char *pDirname );
static int ProcessConfigFile( VarMsgState *pState, char *filename );
static MsgOutputType ParseOutputType( char *outputtype );
static int ProcessQuery( VARSERVER_HANDLE hVarServer,
                         JObject *config,
                         VarQuery *pVarQuery,
                         VarCache **ppVarCache );

static int ProcessTriggerConfig( VarMsgState *pState,
                                 JNode *pNode,
                                 VarMsgConfig *pConfig );

static int ProcessVarsConfig( VarMsgState *pState,
                              JNode *pNode,
                              VarMsgConfig *pConfig );

static int BuildQuery( JObject *config, VarQuery *query );
static int ProcessVarList( JArray *pVarList, VarCache **ppVarCache );
static int AddToCache( JNode *pNode, void *arg );
static int SetupTimer( int s );
static void RunMessageGenerator( VarMsgState *pState );
static int ProcessTimer( VarMsgState *pState );
static int ProcessMessage( VarMsgState *pState, VarMsgConfig *pMsgConfig );
static int RenderMessage( VarMsgState *pState, VarMsgConfig *pMsg, int fd );
static int OutputVar( VAR_HANDLE hVar, void *arg );
static int OutputJSONVar( char prefix, VarInfo *info, char *value, int fd );
static bool IsJSON( char *value );

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

    @retval 0 - no error
    @retval 1 - an error occurred

==============================================================================*/
int main(int argc, char **argv)
{
    int result = EINVAL;

    /* clear the variable message state object */
    memset( &state, 0, sizeof( state ) );

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* set up the abnormal termination handler */
    SetupTerminationHandler();

    /* initialize a memory buffer for output */
    result = SetupVarFP( &state );
    if ( result == EOK )
    {
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
                fprintf( stderr,
                         "At least one configuration must be specified\n");
                usage( argv[0] );
            }

            if ( SetupTimer(1) == EOK )
            {
                RunMessageGenerator( &state );
            }

            /* close the handle to the variable server */
            VARSERVER_Close( hVarServer );
        }

        /* close the output memory buffer */
        VARFP_Close( state.pVarFP );
    }

    return ( result == EOK ) ? 0 : 1;
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
/*  SetupVarFP                                                                */
/*!
    Set up a variable output stream for rendering variables to text

    The SetupVarFP function sets up a shared memory buffer backed by an
    output stream to allow us to render variables (possibly from other
    processes) into a memory buffer.

    @param[in]
        pState
            pointer to the Variable Message State object to initialize

    @retval EOK the Variable Message rendering buffer was created
    @retval EBADF failed to create the memory buffer
    @retval EINVAL invalid arguments

==============================================================================*/
static int SetupVarFP( VarMsgState *pState )
{
    int result = EINVAL;
    char varfp_name[64];
    time_t now;
    int n;
    size_t len = sizeof(varfp_name);

    if ( pState != NULL )
    {
        result = EBADF;

        /* generate a temporary name for the VarFP */
        now = time(NULL);
        n = snprintf(varfp_name, sizeof(varfp_name), "varmsg_%ld", now );
        if ( ( n > 0 ) && ( (size_t)n < len ) )
        {
            /* open a VarFP object for printing */
            pState->pVarFP = VARFP_Open(varfp_name, VARFP_SIZE );
            if ( pState->pVarFP != NULL )
            {
                /* get a file descriptor for the memory buffer */
                pState->varFd = VARFP_GetFd( pState->pVarFP );
                if ( pState->varFd != -1 )
                {
                    result = EOK;
                }
            }
        }
    }

    return result;
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

==============================================================================*/
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

/*============================================================================*/
/*  ProcessConfigFile                                                         */
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
    VarMsgConfig *pConfig;
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
        if ( config != NULL )
        {
            /* allocate a VarMsgConfig object */
            pConfig = calloc( 1, sizeof( VarMsgConfig ) );
            if ( pConfig != NULL )
            {
                /* set the configuration name */
                pConfig->configName = pFileName;

                /* check enabled flag */
                pConfig->enabled = JSON_GetBool( config, "enabled" );

                /* get variable prefix */
                pConfig->prefix = JSON_GetStr( config, "prefix" );

                /* get processing interval */
                JSON_GetNum( config, "interval", &pConfig->interval );
                if ( pConfig->interval != 0 )
                {
                    /* initialize the countdown timer */
                    pConfig->t = pConfig->interval;
                }

                /* process trigger variables */
                result = ProcessTriggerConfig( pState, config, pConfig );

                /* process message body variables */
                result = ProcessVarsConfig( pState, config, pConfig );

                /* increment the number of messages we are handling */
                pState->numMsgs++;

                if ( pState->pMessageConfigs == NULL )
                {
                    /* add the first configuration */
                    pState->pMessageConfigs = pConfig;
                }
                else
                {
                    /* insert the new configuration at the head of the list */
                    pConfig->pNext = pState->pMessageConfigs;
                    pState->pMessageConfigs = pConfig;
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessTriggerConfig                                                      */
/*!
    Process the "trigger" configuration in the JSON config file

    The ProcessTriggerConfig function processes a "trigger" configuration
    attribute in the JSON configuration object.  The trigger can either be
    an explicit list of variables, or a variable search definition object.

    This function will parse the trigger definition and build the
    triggerQuery VarQuery object if the trigger is a search
    definition.

    It will also run the search and populate the trigger cache
    if the trigger is a search definition.

    If the trigger is an explicit variable list, then the handle of each
    variable will be added to the trigger cache.

    @param[in]
        pState
            pointer to the Variable Message Generator state

    @param[in]
        pNode
            pointer to the JNode for the trigger configuration

    @param[in,out]
        pConfig
            pointer to the VarMsgConfig message definition to populate

    @retval EINVAL invalid arguments
    @retval EOK trigger configuration was processed or not specified
    @retval ENOENT one or more variables did not exist
    @retval ENOMEM memory allocation failure

==============================================================================*/
static int ProcessTriggerConfig( VarMsgState *pState,
                                 JNode *pNode,
                                 VarMsgConfig *pConfig )
{
    int result = EINVAL;
    JNode *trigger;

    if ( ( pState != NULL ) &&
         ( pNode != NULL ) &&
         ( pConfig != NULL ) )
    {
        /* process trigger variables */
        trigger = JSON_Find( pNode, "trigger" );
        if ( trigger != NULL )
        {
            if ( trigger->type == JSON_OBJECT )
            {
                /* process a variable query */
                result = ProcessQuery( pState->hVarServer,
                                       (JObject *)trigger,
                                       &(pConfig->triggerQuery),
                                       &(pConfig->pTriggerCache) );
            }
            else if ( trigger->type == JSON_ARRAY )
            {
                /* process a variable list */
                result = ProcessVarList( (JArray *)trigger,
                                         &(pConfig->pTriggerCache) );
            }
        }
        else
        {
            /* trigger configuration is optional since we might just
               be doing a timed message generation */
            result = EOK;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessVarsConfig                                                         */
/*!
    Process the "vars" configuration in the JSON config file

    The ProcessTriggerConfig function processes a "vars" configuration
    attribute in the JSON configuration object.  The vars can either be
    an explicit list of variables, or a variable search definition object.

    This function will parse the vars definition and build the
    varSet VarQuery object if the vars attribute is a search
    definition.

    It will also run the search and populate the vars cache
    if the vars attribute is a search definition.

    If the vars attribute is an explicit variable list, then the handle of each
    variable will be added to the vars cache.

    @param[in]
        pState
            pointer to the Variable Message Generator state

    @param[in]
        pNode
            pointer to the JNode for the trigger configuration

    @param[in,out]
        pConfig
            pointer to the VarMsgConfig message definition to populate

    @retval EINVAL invalid arguments
    @retval EOK trigger configuration was processed or not specified
    @retval ENOENT one or more variables did not exist
    @retval ENOMEM memory allocation failure

==============================================================================*/
static int ProcessVarsConfig( VarMsgState *pState,
                              JNode *pNode,
                              VarMsgConfig *pConfig )
{
    int result = EINVAL;
    JNode *vars;

    if ( ( pState != NULL ) &&
         ( pNode != NULL ) &&
         ( pConfig != NULL ) )
    {
        result = ENOENT;

        /* process message body variables */
        vars = JSON_Find( pNode, "vars" );
        if ( vars != NULL )
        {
            if ( vars->type == JSON_OBJECT )
            {
                /* process a variable query */
                result = ProcessQuery( pState->hVarServer,
                                       (JObject *)vars,
                                       &(pConfig->varSet),
                                       &(pConfig->pVarCache) );
            }
            else if ( vars->type == JSON_ARRAY )
            {
                /* process a variable list */
                result = ProcessVarList( (JArray *)vars,
                                         &(pConfig->pVarCache) );
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
/*  BuildQuery                                                              */
/*!
    Build a Variable Query object from a JSON configuration

    The BuildQuery function processes a variable query JSON object
    which specifies the variable search parameters used to generate
    a list of variables to process.

    A JSON variable query can have one or more of the following attributes:

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
static int BuildQuery( JObject *config, VarQuery *query )
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
        result = EOK;

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

        if ( ( result == EOK ) &&
             ( query->type == 0 ) )
        {
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessQuery                                                              */
/*!
    Process a variable query JSON definition into a variable cache

    The ProcessQuery function processes a variable query JSON object
    which specifies the variable search parameters used to generate
    a list of variables to process and builds a cache of variable handles
    from it.

    If the output variable cache does not exist, then it will be
    created with an initial size of CACHE_SIZE_INITIAL

    A JSON variable query can have one or more of the following attributes:

    instanceID - instance identifier
    match - partial name string match
    flags - flags match ( comma separated list of flags to search for )
    tags - tags match ( comma separated list of tags to search for )

    @param[in]
        hVarServer
            handle to the variable server

    @param[in]
        config
            pointer to a JSON Object containing variable query
            parameters

    @param[in,out]
        pVarQuery
            pointer to a Variable Query object to populate

    @param[in,out]
        ppVarCache
            pointer to a pointer to a Variable Cache to populate.

    @retval EOK the variable query was successfully processed
    @retval EINVAL invalid arguments
    @retval ENOMEM memory

==============================================================================*/
static int ProcessQuery( VARSERVER_HANDLE hVarServer,
                         JObject *config,
                         VarQuery *pVarQuery,
                         VarCache **ppVarCache )
{
    int result = EINVAL;
    size_t len = CACHE_SIZE_INITIAL;
    size_t growBy = CACHE_SIZE_GROW_BY;

    if ( ppVarCache != NULL )
    {
        /* allocate cache if it does not exist */
        if ( *ppVarCache != NULL )
        {
            /* we already have a cache, we don't need to initialize it */
            result = EOK;
        }
        else
        {
            /* initialize the variable cache with a default size */
            result = VARCACHE_Init( ppVarCache, len, growBy );
        }

        if ( result == EOK )
        {
            /* populate a VarQuery object from the JSON query object */
            result = BuildQuery( config, pVarQuery );
            if ( result == EOK )
            {
                /* run the query to build a variable cache */
                result = VARQUERY_CacheUnique( hVarServer,
                                               pVarQuery,
                                               *ppVarCache );
            }
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

/*============================================================================*/
/*  SetupTimer                                                                */
/*!
    Set up a timer

    The SetupTimer function sets up a timer to periodically process the
    message configurations for transmission on a schedule.

    @param[in]
        s
            Timer tick rate (in seconds)

    @retval EOK timer set up ok
    @retval other error from timer_create or timer_settime

==============================================================================*/
static int SetupTimer( int s )
{
    struct sigevent te;
    struct itimerspec its;
    time_t secs = (time_t)s;
    timer_t *timerID;
    int result = EINVAL;
    static timer_t timer = 0;
    int rc;

    timerID = &timer;

    /* Set and enable alarm */
    te.sigev_notify = SIGEV_SIGNAL;
    te.sigev_signo = SIG_VAR_TIMER;
    te.sigev_value.sival_int = 1;
    rc = timer_create(CLOCK_REALTIME, &te, timerID);
    if ( rc == 0 )
    {
        its.it_interval.tv_sec = secs;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = secs;
        its.it_value.tv_nsec = 0;
        rc = timer_settime(*timerID, 0, &its, NULL);
        result = ( rc == 0 ) ? EOK : errno;
    }
    else
    {
        result = errno;
    }

    return result;
}

/*============================================================================*/
/*  RunMessageGenerator                                                       */
/*!
    Run the message generator main loop

    The RunMessageGenerator function waits for an external signal
    either from a timer, or from the variable server.

    @param[in]
        pState
            pointer to the Variable Message Generator state object

    @retval EOK timer set up ok
    @retval other error from timer_create or timer_settime

==============================================================================*/
static void RunMessageGenerator( VarMsgState *pState )
{
    int sig;
    int sigval;
    int result;

    while( 1 )
    {
        /* wait for a received signal */
        sig = VARSERVER_WaitSignal( &sigval );
        if ( sig == SIG_VAR_TIMER )
        {
            /* process received timer signal */
            result = ProcessTimer( pState );
        }
    }
}

/*============================================================================*/
/*  ProcessTimer                                                              */
/*!
    Process a received timer tick

    The ProcessTimer function iterates through all of the Variable
    Message Configurations, and if they are set up to be processed
    on an interval, it will decrement the interval countdown.
    If the interval countdown reaches zero, the Variable Message
    will be processed (generated), and the interval timer will
    be reset to its initial value.

    @param[in]
        pState
            pointer to the Variable Message Generator state object
            containing the Variable Message Configurations to process.

    @retval EOK Timer handler processed successfully
    @retval EINVAL invalid argument

==============================================================================*/
static int ProcessTimer( VarMsgState *pState )
{
    VarMsgConfig *pMsgConfig;
    int result = EINVAL;

    if ( pState != NULL )
    {
        result = EOK;

        /* get the first message configuration */
        pMsgConfig = pState->pMessageConfigs;
        while ( pMsgConfig != NULL )
        {
            /* check if it has an interval processing requirement
               and it is enabled */
            if ( ( pMsgConfig->interval != 0 ) &&
                 ( pMsgConfig->enabled == true ) )
            {
                if ( pMsgConfig->t > 0 )
                {
                    /* decrement the interval countdown */
                    pMsgConfig->t--;
                }

                /* when the interval countdown reaches zero, it is time to
                   process (generate) this message */
                if ( pMsgConfig->t == 0 )
                {
                    /* reset the interval countdown */
                    pMsgConfig->t = pMsgConfig->interval;

                    /* Process (generate) the message */
                    result = ProcessMessage( pState, pMsgConfig );
                }
            }

            /* get the next message configuration */
            pMsgConfig = pMsgConfig->pNext;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessMessage                                                            */
/*!
    Process a Variable Message

    The ProcessMessage function processes a Variable Message.
    Message content is generated if the message is enabled.
    The message is sent to the requested output stream.

    @param[in]
        pState
            pointer to the Variable Message Generator state object
            containing the Variable Message Configurations to process.

    @param[in]
        pMsgConfig
            pointer to the specific variable message to process

    @retval EOK The variable message was successfully processed
    @retval EINVAL invalid argument

==============================================================================*/
static int ProcessMessage( VarMsgState *pState, VarMsgConfig *pMsgConfig )
{
    int result = EINVAL;

    if ( ( pState != NULL ) &&
         ( pMsgConfig != NULL ) )
    {
        /* only process messages which are enabled */
        if( pMsgConfig->enabled == true )
        {
            if ( pState->verbose == true )
            {
                printf("Processing Message: %s\n", pMsgConfig->configName );
            }

            /* render message to standard output */
            result = RenderMessage( pState, pMsgConfig, STDOUT_FILENO );
        }

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  RenderMessage                                                             */
/*!
    Render a Variable Message

    The RenderMessage function renders the specified variable message
    to an output file descriptor.

    @param[in]
        pState
            pointer to the Variable Message Generator state object
            containing the Variable Message Configurations to process.

    @param[in]
        pMsg
            pointer to the specific variable message to render

    @param[in]
        fd
            output file descriptor to write to

    @retval EOK The variable message was successfully rendered
    @retval EINVAL invalid argument

==============================================================================*/
static int RenderMessage( VarMsgState *pState, VarMsgConfig *pMsg, int fd )
{
    int result = EINVAL;

    if ( ( pState != NULL ) &&
         ( pMsg != NULL ) &&
         ( fd != -1 ) )
    {
        /* initialize the variable count for the current render */
        pState->outputCount = 0;

        /* initialize the output file descriptor */
        pState->fd = fd;

        write( fd, "{", 1 );

        /* map the OutputVar function across the variable cache */
        result = VARCACHE_Map( pMsg->pVarCache, OutputVar, (void *)pState );

        write( fd, "}", 1 );
        write( fd, "\n", 1 );

    }

    return result;
}

/*============================================================================*/
/*  OutputVar                                                                 */
/*!
    Output Variable data

    The OutputVar function outputs a variable name/value JSON
    attribute.

    @param[in]
        hVar
            handle to the variable to output

    @param[in]
        arg
            handle to the VarMsgState object

    @retval EOK the variable was output
    @retval EINVAL invalid arguments

==============================================================================*/
static int OutputVar( VAR_HANDLE hVar, void *arg )
{
    VarMsgState *pState = (VarMsgState *)arg;
    char *pData;
    int result = EINVAL;
    int fd;
    char prefix;
    VarInfo info;
    ssize_t n;

    if ( ( pState != NULL ) &&
         ( hVar != VAR_INVALID ) )
    {
        fd = pState->varFd;

        /* get the variable info */
        if ( VAR_GetInfo( pState->hVarServer,
                          hVar,
                          &info ) == EOK )

        {
            /* print the variable value to the output buffer */
            if( VAR_Print( pState->hVarServer,
                           hVar,
                           fd ) == EOK )
            {
                /* NUL terminate */
                n = write( fd, "\0", 1 );
                if ( n != 1 )
                {
                    /* I/O error */
                    result = EIO;
                }

                /* get a handle to the output buffer */
                pData = VARFP_GetData( pState->pVarFP );
                if( pData != NULL )
                {
                    /* see if we need to prepend a comma */
                    prefix = ( pState->outputCount > 0 ) ? ',' : ' ';

                    /* output the data */
                    OutputJSONVar( prefix, &info, pData, pState->fd );

                    /* clear the memory */
                    pData[0] = '\0';

                    /* increment the variable count */
                    pState->outputCount++;

                    result = EOK;
                }
            }

            /* seek to the beginning of the output buffer */
            lseek( fd, 0, SEEK_SET );
        }
    }

    return result;
}

/*============================================================================*/
/*  OutputJSONVar                                                             */
/*!
    Output a variable JSON value

    The OutputJSONVar function prints a variable JSON value with a prefix
    The prefix is intended to be either a space, or a comma so this
    function can be used to output a list of variables and prepend (or not)
    a comma.

    The output will be similar to the following:

    "name" : "value"

    @param[in]
        info
            pointer to the variable information

    @param[in]
        value
            value of the variable as a string

    @param[in]
        fd
            output file descriptor

    @retval EOK the JSON value was output
    @retval EINVAL invalid arguments

==============================================================================*/
static int OutputJSONVar( char prefix, VarInfo *info, char *value, int fd )
{
    int result = EINVAL;

    if ( ( info != NULL ) &&
         ( value != NULL ) )
    {
        if (IsJSON( value ) == true )
        {
            if ( info->instanceID == 0 )
            {
                dprintf( fd,
                        "%c\"%s\":%s",
                        prefix,
                        info->name,
                        value );
            }
            else
            {
                dprintf( fd,
                        "%c\"[%d]%s\":%s",
                        prefix,
                        info->instanceID,
                        info->name,
                        value );
            }
        }
        else
        {
            if ( info->instanceID == 0 )
            {
                dprintf( fd,
                        "%c\"%s\":\"%s\"",
                        prefix,
                        info->name,
                        value );
            }
            else
            {
                dprintf( fd,
                        "%c\"[%d]%s\":\"%s\"",
                        prefix,
                        info->instanceID,
                        info->name,
                        value );
            }
        }

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  IsJSON                                                                    */
/*!
    Determine if the string is a JSON object

    The IsJSON function examines the non-whitespace characters at the
    beginning and end of the value to determine if the value is likely
    a JSON object.  If the first and last non-whitespace characters are
    [ and ] or { and }, then the value is likely a JSON object

    @param[in]
        value
            value to be checked to see if it is JSON


    @retval true the value is likely a JSON object
    @retval false the value is not a JSON object

==============================================================================*/
static bool IsJSON( char *value )
{
    char c_start = ' ';
    char c_end = ' ';
    bool result = false;
    int i=0;
    int len;

    if ( value != NULL )
    {
        // get the length of the string
        len = strlen(value);
        if ( len > 0 )
        {
            // get the first non-space character at the
            // beginning of the value
            while(isspace(value[i]) && ( i < len))
            {
                i++;
            }

            if ( i < len )
            {
                c_start = value[i];
            }

            // search for the first non-whitespace character at the
            // end of the value
            i = len-1;
            while(isspace(value[i]) && ( i >= 0 ))
            {
                i--;
            }

            if ( i >= 0 )
            {
                c_end = value[i];
            }

            // check if we have a JSON object
            if ( ( c_start == '[' && c_end == ']' ) ||
                ( c_start == '{' && c_end == '}' ) )
            {
                // probably a JSON object since the start and end
                // characters of the value are '
                result = true;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );
    sigaction( SIGINT, &sigact, NULL );

}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server and cleans up any open
    resources.

@param[in]
    signum
        The signal which caused the abnormal termination (unused)

@param[in]
    info
        pointer to a siginfo_t object (unused)

@param[in]
    ptr
        signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

    printf("Abnormal termination of varmsg service\n" );

    if ( state.hVarServer != NULL )
    {
        VARSERVER_Close( state.hVarServer );
    }

    if ( state.pVarFP != NULL )
    {
        /* close the output memory buffer */
        VARFP_Close( state.pVarFP );
    }

    exit( 1 );
}

/*! @}
 * end of varmsg group */
