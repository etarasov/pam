-- http://www.linux-pam.org/
-- http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html

module System.Posix.PAM where

import Foreign.Ptr
import System.Posix.PAM.LowLevel
import System.Posix.PAM.Types

authenticate :: String -> String -> String -> IO (Either Int ())
authenticate serviceName userName password = do
    let custConv :: String -> PamConv
        custConv pass _ messages = do
            let rs = map (\ _ -> PamResponse pass) messages
            return rs
    (pamH, r1) <- pamStart serviceName userName (custConv password, nullPtr)
    case r1 of
        PamRetCode code -> return $ Left $ fromInteger $ toInteger code
        PamSuccess -> do
            r2 <- pamAuthenticate pamH (PamFlag 0)
            case r2 of
                PamRetCode code -> return $ Left $ fromInteger $ toInteger code
                PamSuccess -> do
                    r3 <- pamEnd pamH r2
                    case r3 of
                        PamSuccess -> return $ Right ()
                        PamRetCode code -> return $ Left $ fromInteger $ toInteger code

checkAccount :: String -> String -> IO (Either Int ())
checkAccount = undefined


pamCodeToMessage :: Int -> String
pamCodeToMessage = snd . pamCodeDetails

pamCodeToCDefine :: Int -> String
pamCodeToCDefine = fst . pamCodeDetails

pamCodeDetails :: Int -> (String, String)
pamCodeDetails code = case code of
    0 -> ("PAM_SUCCESS", "Successful function return")
    1 -> ("PAM_OPEN_ERR", "dlopen() failure when dynamically loading a service module")
    2 -> ("PAM_SYMBOL_ERR", "Symbol not found")
    3 -> ("PAM_SERVICE_ERR", "Error in service module")
    4 -> ("PAM_SYSTEM_ERR", "System error")
    5 -> ("PAM_BUF_ERR", "Memory buffer error")
    6 -> ("PAM_PERM_DENIED", "Permission denied")
    7 -> ("PAM_AUTH_ERR", "Authentication failure")
    8 -> ("PAM_CRED_INSUFFICIENT", "Can not access authentication data due to insufficient credentials")
    9 -> ("PAM_AUTHINFO_UNAVAIL", "Underlying authentication service can not retrieve authentication information")
    10 -> ("PAM_USER_UNKNOWN", "User not known to the underlying authenticaiton module")
    11 -> ("PAM_MAXTRIES", "An authentication service has maintained a retry count which has been reached.  No further retries should be attempted")
    12 -> ("PAM_NEW_AUTHTOK_REQD", "New authentication token required. This is normally returned if the machine security policies require that the password should be changed beccause the password is NULL or it has aged")
    13 -> ("PAM_ACCT_EXPIRED", "User account has expired")
    14 -> ("PAM_SESSION_ERR", "Can not make/remove an entry for the specified session")
    15 -> ("PAM_CRED_UNAVAIL", "Underlying authentication service can not retrieve user credentials unavailable")
    16 -> ("PAM_CRED_EXPIRED", "User credentials expired")
    17 -> ("PAM_CRED_ERR", "Failure setting user credentials")
    18 -> ("PAM_NO_MODULE_DATA", "No module specific data is present")
    19 -> ("PAM_CONV_ERR", "Conversation error")
    20 -> ("PAM_AUTHTOK_ERR", "Authentication token manipulation error")
    21 -> ("PAM_AUTHTOK_RECOVERY_ERR", "Authentication information cannot be recovered")
    22 -> ("PAM_AUTHTOK_LOCK_BUSY", "Authentication token lock busy")
    23 -> ("PAM_AUTHTOK_DISABLE_AGING", "Authentication token aging disabled")
    24 -> ("PAM_TRY_AGAIN", "Preliminary check by password service")
    25 -> ("PAM_IGNORE", "Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient")
    26 -> ("PAM_ABORT", "Critical error (?module fail now request)")
    27 -> ("PAM_AUTHTOK_EXPIRED", "user's authentication token has expired")
    28 -> ("PAM_MODULE_UNKNOWN", "module is not known")
    29 -> ("PAM_BAD_ITEM", "Bad item passed to pam_*_item()")
    30 -> ("PAM_CONV_AGAIN", "conversation function is event driven and data is not available yet")
    31 -> ("PAM_INCOMPLETE", "please call this function again to complete authentication stack. Before calling again, verify that conversation is completed")
    a -> ("PAM_UNKNOWN", "There is no code description in haskell pam library: " ++ show a)
