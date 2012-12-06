
module System.Posix.PAM.LowLevel where

import Foreign.C
import Foreign.Marshal.Array
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import System.Posix.PAM.Types
import System.Posix.PAM.Internals hiding (resp, conv)

retCodeFromC :: CInt -> PamRetCode
retCodeFromC rc = case rc of
            0 -> PamSuccess
            a -> PamRetCode $ fromInteger $ toInteger a

retCodeToC :: PamRetCode -> CInt
retCodeToC PamSuccess = 0
retCodeToC (PamRetCode a) = fromInteger $ toInteger a

responseToC :: PamResponse -> IO CPamResponse
responseToC (PamResponse resp) = do
    resp' <- newCString resp
    return $ CPamResponse resp' 0

messageFromC :: CPamMessage -> IO PamMessage
messageFromC cmes =
    let style = case msg_style cmes of
            1 -> PamPromptEchoOff
            2 -> PamPromptEchoOn
            3 -> PamErrorMsg
            4 -> PamTextInfo
            a -> error $ "unknown style value: " ++ show a
    in do
        str <- peekCString $ msg cmes
        return $ PamMessage str style

cConv :: (Ptr () -> [PamMessage] -> IO [PamResponse]) -> CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
cConv customConv num mesArrPtr respArrPtr appData =
    if num <= 0
        then return 19
        else do
            -- get array pointer (pointer to first element)
            voidArr <- peek mesArrPtr

            -- cast pointer type from ()
            let mesArr = castPtr voidArr :: Ptr CPamMessage

            -- peek message list from array
            cMessages <- peekArray (fromInteger $ toInteger num) mesArr

            -- convert messages into high-level types
            messages <- mapM messageFromC cMessages

            -- create response list
            responses <- customConv appData messages

            -- convert responses into low-level types
            cResponses <- mapM responseToC responses

            -- alloc memory for response array
            respArr <- mallocArray (fromInteger $ toInteger num)

            -- poke resonse list into array
            pokeArray respArr cResponses

            -- poke array pointer into respArrPtr
            poke respArrPtr $ castPtr respArr

            -- return PAM_SUCCESS
            return 0


pamStart :: String -> String -> (PamConv, Ptr ()) -> IO (PamHandle, PamRetCode)
pamStart serviceName userName (pamConv, appData) = do
    cServiceName <- newCString serviceName
    cUserName <- newCString userName

    -- create FunPtr pointer to function and embedd PamConv function into cConv
    pamConvPtr <- mkconvFunc $ cConv pamConv
    let conv = CPamConv pamConvPtr appData

    convPtr <- malloc
    poke convPtr conv

    pamhPtr <- malloc
    poke pamhPtr nullPtr

    r1 <- c_pam_start cServiceName cUserName convPtr pamhPtr

    cPamHandle_ <- peek pamhPtr

    let retCode = case r1 of
            0 -> PamSuccess
            a -> PamRetCode $ fromInteger $ toInteger a

    free cServiceName
    free cUserName
    free convPtr

    free pamhPtr

    return (PamHandle cPamHandle_ pamConvPtr, retCode)

pamEnd :: PamHandle -> PamRetCode -> IO PamRetCode
pamEnd pamHandle inRetCode = do
    let cRetCode = case inRetCode of
            PamSuccess -> 0
            PamRetCode a -> fromInteger $ toInteger a
    r <- c_pam_end (cPamHandle pamHandle) cRetCode
    freeHaskellFunPtr $ cPamCallback pamHandle

    return $ retCodeFromC r

pamAuthenticate :: PamHandle -> PamFlag -> IO PamRetCode
pamAuthenticate pamHandle (PamFlag flag) = do
    let cFlag = fromInteger $ toInteger flag
    r <- c_pam_authenticate (cPamHandle pamHandle) cFlag
    return $ retCodeFromC r

pamAcctMgmt :: PamHandle -> PamFlag -> IO PamRetCode
pamAcctMgmt pamHandle (PamFlag flag) = do
    let cFlag = fromInteger $ toInteger flag
    r <- c_pam_acct_mgmt (cPamHandle pamHandle) cFlag
    return $ retCodeFromC r
