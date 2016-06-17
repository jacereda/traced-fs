module Main where

import           Control.Concurrent.MVar
import           Control.Monad
import           Control.Monad.Reader
import           Data.List
import           Data.Char
import           Data.Maybe
import           System.Directory
import           System.Exit
import           System.FilePath
import           System.Info
import           System.IO
import           System.IO.Temp
import           System.IO.Unsafe
import           System.Process
import           System.Process.Internals
import           System.Posix.Process
import           Test.QuickCheck
import           Test.QuickCheck.Monadic
import           Test.QuickCheck.Test
import           Debug.Trace

data Env = Env { shellMode :: ShellMode
               , traceMode :: TraceMode
               , spaceMode :: SpaceMode
               , tmpDir :: FilePath
               }

type Prop = Reader Env Property

newtype Arg = Arg { unarg :: String } deriving (Show, Eq)

instance Arbitrary Arg where
  arbitrary = liftM Arg $ listOf1 validChars
    where validChars = arbitrary `suchThat` (`notElem` "\0")

newtype Path = Path { unpath :: FilePath }

instance Eq Path where
  (==) (Path a) (Path b) = equalFilePath a b

instance Show Path where
  show (Path p) = show p

instance Ord Path where
  compare (Path x) (Path y) = compare (cased x) (cased y)


isWindows :: Bool
isWindows = os == "mingw32"

outputFrom :: [String] -> IO (Maybe String)
outputFrom (cmd:args) = do
  (rc,out,err) <- readProcessWithExitCode cmd args ""
  when (err /= "") $ putStrLn err
  return $ if rc == ExitSuccess then Just out else Nothing
outputFrom _ = undefined

errorFrom :: [String] -> IO String
errorFrom (cmd:args) = do
  (_,_,err) <- readProcessWithExitCode cmd args ""
  return err
errorFrom _ = undefined


mpt :: FilePath
mpt = "traced"

parsedOutputFrom :: [String] -> IO (Maybe [Access])
parsedOutputFrom (cmd:args) = do
  (_, Just outh, _, pid) <- createProcess (proc cmd args) { std_out = CreatePipe }
  let (ProcessHandle phmv _) = pid in readMVar phmv >>= \phv -> case phv of
            ClosedHandle _ -> error "process handle is closed"
            OpenHandle ph -> do
              _ <- hGetContents outh
              rc <- waitForProcess pid
              acc <- readFile $ mpt </> ".ops" </> show ph
              return $ if rc == ExitSuccess then Just (parse acc) else Nothing
parsedOutputFrom _ = return Nothing

toStandard :: FilePath -> FilePath
toStandard = if isWindows then map (\x -> if x == '\\' then '/' else x) else id

parseDeps :: Maybe String -> [FilePath]
parseDeps = filter (/= " ") . map unhack . words . hack . drop 1 . dropWhile (/= ':') . fromMaybe ""
  where hack ('\\':' ':xs) = '^':hack xs
        hack ('\\':'\n':xs) = ' ':hack xs
        hack (x:xs) = x:hack xs
        hack [] = []
        unhack = map (\x -> if x == '^' then ' ' else x)

parseClDeps :: String -> [FilePath]
parseClDeps = mapMaybe parseLine . lines
  where parseLine ('N':xs) = Just $ dropWhile (== ' ') $ skip ':' $ skip ':' xs
        parseLine _ = Nothing
        skip c = drop 1 . dropWhile (/= c)

yields :: Reader Env [String] -> Reader Env [Access] -> Prop
yields eargs eres = do
  e <- ask
  return $ monadicIO $ do
    let args = runReader eargs e
        res = runReader eres e
    r <- run $ parsedOutputFrom args
    let sr | isJust r = Just $ nub $ sort $ filter (valid $ tmpDir e) $ fromJust r
           | otherwise = Nothing
        ok = sr == Just res
    unless ok $ run $ do
      putStrLn $ "Expecting " ++ show res
      putStrLn $ "Got       " ++ show sr
    assert ok

data ShellMode = Unshelled | Shelled deriving (Show, Eq, Enum, Bounded)
data TraceMode = Traced | Untraced deriving (Show, Eq, Enum, Bounded)
data SpaceMode = Unspaced | Spaced deriving (Show, Eq, Enum, Bounded)

command :: [String] -> Reader Env [String]
command args = do
  e <- ask
  return $ cmd (shellMode e) (traceMode e)
  where cmd :: ShellMode -> TraceMode -> [String]
        cmd sm Traced = cmd sm Untraced 
        cmd Unshelled _ = args
        cmd Shelled _ | isWindows = "cmd.exe" : "/C" : args
                      | otherwise = ["sh", "-c", unwords (map quoted args)]
        quoted :: String -> String
        quoted "|" = "|"
        quoted ">" = ">"
        quoted x = "\"" ++ x ++ "\""

whenTracing :: [a] -> Reader Env [a]
whenTracing x = do
  e <- ask
  return $ if traceMode e == Traced then x else []

prop_echo :: Path -> Path -> Prop
prop_echo src dst = command ["echo", unpath src, "|", "sort" , ">", unpath dst] `yields` return [W dst]

prop_cp :: Path -> Path -> Prop
prop_cp src dst = command ["cp", unpath src, unpath dst] `yields` whenTracing [R src, W dst]

prop_mv :: Path -> Path -> Prop
prop_mv src dst = command ["mv", unpath src, unpath dst] `yields` whenTracing [M dst src]

prop_touch :: Path -> Prop
prop_touch dst = command ["touch", unpath dst] `yields` whenTracing [T dst]

prop_rm :: Path -> Prop
prop_rm dst = command ["rm", unpath dst] `yields` whenTracing [D dst]

prop_gcc :: Path -> [Access] -> Prop
prop_gcc src deps = command ["gcc", "-E", unpath src] `yields` whenTracing deps

prop_cl :: Path -> [Access] -> Prop 
prop_cl src deps = command ["cl", "/nologo", "/E", unpath src] `yields` whenTracing deps

main :: IO ()
main = sequence [allTests sp sm tm | sp <- allValues, sm <- allValues, tm <- allValues]
       >>= mapM_ (mapM_ chk)
  where chk x = unless (isSuccess x) exitFailure
        noisy s = putStrLn ("Testing " ++ s)
        banner x = putStrLn $ "================ " ++ x ++ " ================"
        dirname Unspaced = "tracedfs"
        dirname Spaced = "tracedfs with spaces"
        allValues :: (Enum a, Bounded a) => [a]
        allValues = enumFrom minBound
        allTests :: SpaceMode -> ShellMode -> TraceMode -> IO [Result]
        allTests sp sm tm = withSystemTempDirectory (dirname sp) $ \utmp -> do -- bracket (spawnProcess "../fsd" [mpt]) terminateProcess $ \_ ->
          pid <- getProcessID
          putStrLn $ show pid
          _ <- doesFileExist $ mpt </> ".rootpid-" ++ show pid
          t <- canonicalizePath utmp
          banner $ show sp ++ " " ++ show sm ++ " " ++ show tm
          src <- canonicalizePath $ ".." </> "src"
          cl <- findExecutable "cl.exe"
          let hascl = isJust cl
              tsrc = mpt ++ t </> "src"
              tlc = Path $ tsrc </> "toplevel.c"
              srcc = Path $ tsrc </> "src.c"
              clcsrc = Path $ tsrc </> "win" </> "handle.c"
              rvalid = sort . filter (valid t) . map (R . Path)
              e = Env {shellMode = sm, traceMode = tm, spaceMode = sp, tmpDir = t}
              qc s p = noisy s >> quickCheckWithResult (stdArgs {maxSuccess=1}) (runReader p e)
          _ <- callProcess "cp" ["-R", src, tsrc]
          deps <- outputFrom ["gcc", "-MM", unpath tlc]
          ndeps <- mapM canonicalizePath (parseDeps deps)
          cldeps <- if hascl then errorFrom ["cl", "/nologo", "/showIncludes", "/E", "/DPATH_MAX=4096", unpath clcsrc] else return []
          ncldeps <- if hascl then mapM canonicalizePath (unpath clcsrc : parseClDeps cldeps) else return []
          sequence $
            [ qc "gcc" $ prop_gcc tlc (rvalid ndeps)
            , qc "cp" $ prop_cp tlc srcc
            , qc "touch" $ prop_touch srcc
            , qc "rm" $ prop_rm srcc
            , qc "mv" $ prop_mv tlc srcc
            ]
            ++ [qc "cl" $ prop_cl clcsrc (rvalid ncldeps) | hascl]
            ++ [qc "echo" $ prop_echo tlc srcc | sm == Shelled && tm == Traced]
            

data Access = R Path
            | W Path
            | D Path
            | Q Path
            | T Path
            | M Path Path
            deriving (Show, Eq, Ord)

parse :: String -> [Access]
parse = mapMaybe f . lines
    where f ('w':'|':xs) = Just $ W $ Path xs
          f ('r':'|':xs) = Just $ R $ Path xs
          f ('d':'|':xs) = Just $ D $ Path xs
          f ('q':'|':xs) = Just $ Q $ Path xs
          f ('t':'|':xs) = Just $ T $ Path xs
          f ('m':'|':xs) | (xs','|':ys) <- break (== '|') xs = Just $ M (Path xs') (Path ys)
          f _ = Nothing

cased :: String -> String
cased | isWindows = map toLower
      | otherwise = id

cd :: FilePath
{-# NOINLINE cd #-}
cd = unsafePerformIO (getCurrentDirectory >>= canonicalizePath)

valid :: FilePath -> Access -> Bool
valid t (R p) = inTraced t p
valid t (Q p) = inTraced t p
valid t (W p) = inTraced t p
valid t (D p) = inTraced t p
valid t (T p) = inTraced t p
valid t (M p _) = inTraced t p

inTraced :: FilePath -> Path -> Bool
inTraced t = isPrefixOf (cased t) . cased . unpath
