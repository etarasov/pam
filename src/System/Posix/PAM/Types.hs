
module System.Posix.PAM.Types where

import Foreign.C
import Foreign.Ptr

data PamMessage = PamMessage { pmString :: String
                             , pmStyle :: PamStyle
                             }
                             deriving (Show, Eq)

data PamStyle = PamPromptEchoOff
              | PamPromptEchoOn
              | PamErrorMsg
              | PamTextInfo
              deriving (Show, Eq)

{- | http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv
 - resp_code member in C sturct is unused and should be set to zero, that's why there is no code field in the haskell data type
 -}
data PamResponse = PamResponse String
                 deriving (Show, Eq)

data PamRetCode = PamSuccess
                | PamRetCode Int
                deriving (Show, Eq)

data PamFlag = PamFlag Int

type PamConv = Ptr () -> [PamMessage] -> IO [PamResponse]


data PamHandle = PamHandle { cPamHandle :: Ptr ()
                           , cPamCallback :: FunPtr (CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt)
                           }
                           deriving (Show, Eq)
