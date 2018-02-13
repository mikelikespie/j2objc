load(":j2objc_provider.bzl", "J2ObjCInfo")


DEFAULT_INCLUDES = [
  "android/platform/libcore/ojluni/src/main/java/"
]

def merge_objc_providers(providers):
  current = {}
  for p in providers:
    for k in dir(p):
      attr = getattr(p, k)
      if attr:
        if k not in current:
          current[k] = depset()
        current[k] += attr
  return apple_common.new_objc_provider(**current)

#def _j2objc_source():

ALWAYS_ON_FLAGS = [
  "-encoding", "UTF-8",
  "--doc-comments",
  "-XcombineJars",
  "-Xtranslate-bootclasspath"
]
def create_j2objc_transpilation_action(
    ctx,
    name,
    java,
    j2objc,
    j2objc_wrapper,
    compiled_archive,
    xcrun_wrapper,
    xcode_config,
    libtool,
    clang,
    objc_fragment,
    sources = [],
    source_jars = [],
    deps = [],
):

  outout_header_mapping_file = ctx.actions.declare_file("{}.mapping.j2objc".format(name))
  output_dependency_mapping_file = ctx.actions.declare_file("{}.dependency_mapping.j2objc".format(name))
  output_archive_source_mapping_file = ctx.actions.declare_file("{}.archive_source_mapping.j2objc".format(name))

  build_file_base = '/'.join(ctx.build_file_path.split('/')[:-1])

  output_root = ctx.bin_dir.path

  if build_file_base.startswith("external/"):
    prefix_to_truncate = '/'.join(build_file_base.split('/')[2:])
    extra_root = '/'.join(build_file_base.split('/')[:2])
    output_root += '/' + extra_root
  else:
    prefix_to_truncate = build_file_base
    extra_root = ""


  source_basenames = depset()

  for s in sources:
    basename = s.path[:-len('.java')]

    # we want to remove the prefix that overlaps with our build

    if not basename.startswith(prefix_to_truncate):
      fail("Unexpected state")

    source_basenames += [basename]

  objc_file_path = output_root + "/" + build_file_base + "/_j2objc_objc_{}".format(name)

  j2objc_args = ctx.actions.args()

  j2objc_inputs = depset()
  j2objc_outputs = depset()

  j2objc_args.add(ALWAYS_ON_FLAGS)

  j2objc_args.add("--java")
  j2objc_args.add(java.path)
  j2objc_inputs += [java]

  j2objc_args.add("--j2objc")
  j2objc_args.add(j2objc.path)
  j2objc_inputs += [j2objc]

  j2objc_args.add("--main_class")
  j2objc_args.add("com.google.devtools.j2objc.J2ObjC")

  j2objc_args.add("--objc_file_path")
  j2objc_args.add(objc_file_path)

  j2objc_args.add("--output_dependency_mapping_file")
  j2objc_args.add(output_dependency_mapping_file.path)
  j2objc_outputs += [output_dependency_mapping_file]

  header_mapping_files = depset()
  for d in deps:
    if J2ObjCInfo not in d:
      continue
    header_mapping_files += d[J2ObjCInfo].header_mapping_files

  if header_mapping_files:
    j2objc_args.add("--header-mapping")
    j2objc_args.add(header_mapping_files, join_with=",")
    j2objc_inputs += header_mapping_files

  j2objc_args.add("--output-header-mapping")
  j2objc_args.add(outout_header_mapping_file.path)
  j2objc_outputs += [outout_header_mapping_file]

  class_mapping_files = depset()
  for d in deps:
    if J2ObjCInfo not in d:
      continue
    class_mapping_files += d[J2ObjCInfo].class_mapping_files

  if class_mapping_files:
      j2objc_args.add("--mapping")
      j2objc_args.add(class_mapping_files, join_with=",")
      j2objc_inputs += class_mapping_files

  j2objc_args.add("--output_archive_source_mapping_file")
  j2objc_args.add(output_archive_source_mapping_file.path)
  j2objc_outputs += [output_archive_source_mapping_file]

  j2objc_args.add("--compiled_archive_file_path")
  j2objc_args.add(compiled_archive)

  #TODO: add srcjar support ehre

  j2objc_args.set_param_file_format("multiline")
  j2objc_args.use_param_file("@%s", use_always = True)

  j2objc_args.add("-d")
  j2objc_args.add(objc_file_path)

  compile_jars = depset()
  for d in deps:
    if JavaInfo not in d:
      continue
    compile_jars += d[JavaInfo].transitive_compile_time_jars

  if compile_jars:
    j2objc_args.add("-classpath")
    j2objc_args.add(compile_jars, join_with = ":")
    j2objc_inputs += compile_jars

  dead_code_report = """\
android.os.AsyncTask
android.os.AsyncTask$1
android.os.AsyncTask$1WorkerRunnableImpl
android.os.AsyncTask$2
android.os.AsyncTask$3
android.os.AsyncTask$SerialExecutor
android.os.AsyncTask$SerialExecutor$1
android.os.AsyncTask$Status
android.os.AsyncTask$WorkerRunnable
android.os.SystemClock
android.system.ErrnoException
android.system.GaiException
android.system.StructAddrinfo
android.test.suitebuilder.annotation.LargeTest
android.test.suitebuilder.annotation.MediumTest
android.test.suitebuilder.annotation.SmallTest
android.test.suitebuilder.annotation.Smoke
android.test.suitebuilder.annotation.Suppress
android.text.Editable
android.text.Editable$Factory
android.text.GetChars
android.text.InputFilter
android.text.InputFilter$AllCaps
android.text.InputFilter$LengthFilter
android.text.InputType
android.text.NoCopySpan
android.text.NoCopySpan$Concrete
android.text.Selection
android.text.Selection$1
android.text.Selection$END
android.text.Selection$START
android.text.SpanSet
android.text.SpanWatcher
android.text.Spannable
android.text.Spannable$Factory
android.text.SpannableString
android.text.SpannableStringBuilder
android.text.SpannableStringInternal
android.text.Spanned
android.text.SpannedString
android.text.TextUtils
android.text.TextUtils$SimpleStringSplitter
android.text.TextUtils$StringSplitter
android.text.TextUtils$TruncateAt
android.text.TextWatcher
android.text.util.Rfc822Token
android.text.util.Rfc822Tokenizer
android.util.ArrayMap
android.util.ArrayMap$1InteropMapCollections
android.util.ArraySet
android.util.ArraySet$1InteropMapCollections
android.util.Base64
android.util.Base64$Coder
android.util.Base64$Decoder
android.util.Base64$Encoder
android.util.Base64DataException
android.util.Base64InputStream
android.util.Base64OutputStream
android.util.ContainerHelpers
android.util.Log
android.util.Log$1
android.util.Log$TerribleFailure
android.util.Log$TerribleFailureHandler
android.util.LruCache
android.util.MapCollections
android.util.MapCollections$ArrayIterator
android.util.MapCollections$EntrySet
android.util.MapCollections$KeySet
android.util.MapCollections$MapIterator
android.util.MapCollections$ValuesCollection
android.util.Pair
android.util.Printer
android.util.SparseArray
android.util.SparseBooleanArray
android.util.SparseIntArray
android.util.SparseLongArray
com.android.internal.util.ArrayUtils
com.google.android.collect.Lists
com.google.android.collect.Maps
com.google.android.collect.Sets
com.google.j2objc.LibraryNotLinkedError
com.google.j2objc.ReflectionStrippedError
com.google.j2objc.WeakProxy
com.google.j2objc.annotations.AutoreleasePool
com.google.j2objc.annotations.J2ObjCIncompatible
com.google.j2objc.annotations.LoopTranslation
com.google.j2objc.annotations.LoopTranslation$LoopStyle
com.google.j2objc.annotations.ObjectiveCName
com.google.j2objc.annotations.Property
com.google.j2objc.annotations.ReflectionSupport
com.google.j2objc.annotations.ReflectionSupport$Level
com.google.j2objc.annotations.RetainedLocalRef
com.google.j2objc.annotations.RetainedWith
com.google.j2objc.annotations.Weak
com.google.j2objc.annotations.WeakOuter
com.google.j2objc.io.AsyncPipedNSInputStreamAdapter
com.google.j2objc.io.AsyncPipedNSInputStreamAdapter$Delegate
com.google.j2objc.io.AsyncPipedNSInputStreamAdapter$OutputStreamAdapter
com.google.j2objc.net.DataEnqueuedInputStream
com.google.j2objc.net.DataEnqueuedOutputStream
com.google.j2objc.net.IosHttpHandler
com.google.j2objc.net.IosHttpURLConnection
com.google.j2objc.net.IosHttpURLConnection$1
com.google.j2objc.net.IosHttpURLConnection$CookieSplitter
com.google.j2objc.net.IosHttpURLConnection$HeaderEntry
com.google.j2objc.net.IosHttpsHandler
com.google.j2objc.net.IosHttpsURLConnection
com.google.j2objc.net.NSErrorException
com.google.j2objc.net.SecurityDataHandler
com.google.j2objc.nio.charset.IOSCharset
com.google.j2objc.nio.charset.IconvCharsetDecoder
com.google.j2objc.nio.charset.IconvCharsetEncoder
com.google.j2objc.security.IosMD5MessageDigest
com.google.j2objc.security.IosRSAKey
com.google.j2objc.security.IosRSAKey$IosRSAPrivateKey
com.google.j2objc.security.IosRSAKey$IosRSAPublicKey
com.google.j2objc.security.IosRSAKeyFactory
com.google.j2objc.security.IosRSAKeyPairGenerator
com.google.j2objc.security.IosRSASignature
com.google.j2objc.security.IosRSASignature$MD5RSA
com.google.j2objc.security.IosRSASignature$SHA1RSA
com.google.j2objc.security.IosRSASignature$SHA256RSA
com.google.j2objc.security.IosRSASignature$SHA384RSA
com.google.j2objc.security.IosRSASignature$SHA512RSA
com.google.j2objc.security.IosSHAMessageDigest
com.google.j2objc.security.IosSHAMessageDigest$SHA1
com.google.j2objc.security.IosSHAMessageDigest$SHA256
com.google.j2objc.security.IosSHAMessageDigest$SHA384
com.google.j2objc.security.IosSHAMessageDigest$SHA512
com.google.j2objc.security.IosSecureRandomImpl
com.google.j2objc.security.IosSecurityProvider
com.google.j2objc.security.cert.IosCertificateFactory
com.google.j2objc.security.cert.IosX509Certificate
com.google.j2objc.util.NativeTimeZone
com.google.j2objc.util.PropertiesXmlLoader
com.google.j2objc.util.PropertiesXmlLoader$1
com.google.j2objc.util.logging.IOSLogHandler
com.google.j2objc.util.logging.IOSLogHandler$IOSLogFormatter
dalvik.system.BlockGuard
dalvik.system.BlockGuard$1
dalvik.system.BlockGuard$2
dalvik.system.BlockGuard$BlockGuardPolicyException
dalvik.system.BlockGuard$Policy
dalvik.system.CloseGuard
dalvik.system.CloseGuard$1
dalvik.system.CloseGuard$DefaultReporter
dalvik.system.CloseGuard$DefaultTracker
dalvik.system.CloseGuard$Reporter
dalvik.system.CloseGuard$Tracker
dalvik.system.SocketTagger
dalvik.system.SocketTagger$1
java.awt.font.NumericShaper
java.awt.font.NumericShaper$1
java.awt.font.NumericShaper$Range
java.awt.font.NumericShaper$Range$1
java.awt.font.TextAttribute
java.beans.BeanDescriptor
java.beans.BeanInfo
java.beans.ChangeListenerMap
java.beans.EventSetDescriptor
java.beans.FeatureDescriptor
java.beans.IndexedPropertyChangeEvent
java.beans.IndexedPropertyDescriptor
java.beans.IntrospectionException
java.beans.Introspector
java.beans.MethodDescriptor
java.beans.ParameterDescriptor
java.beans.PropertyChangeEvent
java.beans.PropertyChangeListener
java.beans.PropertyChangeListenerProxy
java.beans.PropertyChangeSupport
java.beans.PropertyChangeSupport$1
java.beans.PropertyChangeSupport$PropertyChangeListenerMap
java.beans.PropertyDescriptor
java.beans.PropertyVetoException
java.beans.SimpleBeanInfo
java.beans.StandardBeanInfo
java.beans.StandardBeanInfo$1
java.beans.StandardBeanInfo$PropertyComparator
java.io.BufferedInputStream
java.io.BufferedOutputStream
java.io.BufferedReader
java.io.BufferedReader$1
java.io.BufferedWriter
java.io.ByteArrayInputStream
java.io.ByteArrayOutputStream
java.io.CharArrayReader
java.io.CharArrayWriter
java.io.CharConversionException
java.io.Closeable
java.io.Console
java.io.Console$ConsoleReader
java.io.Console$ConsoleWriter
java.io.DataInput
java.io.DataInputStream
java.io.DataOutput
java.io.DataOutputStream
java.io.EOFException
java.io.EmulatedFields
java.io.EmulatedFields$ObjectSlot
java.io.EmulatedFieldsForDumping
java.io.EmulatedFieldsForLoading
java.io.Externalizable
java.io.File
java.io.FileDescriptor
java.io.FileFilter
java.io.FileInputStream
java.io.FileNotFoundException
java.io.FileOutputStream
java.io.FilePermission
java.io.FileReader
java.io.FileWriter
java.io.FilenameFilter
java.io.FilterInputStream
java.io.FilterOutputStream
java.io.FilterReader
java.io.FilterWriter
java.io.Flushable
java.io.IOError
java.io.IOException
java.io.InputStream
java.io.InputStreamReader
java.io.InterruptedIOException
java.io.InvalidClassException
java.io.InvalidObjectException
java.io.LineNumberInputStream
java.io.LineNumberReader
java.io.NotActiveException
java.io.NotSerializableException
java.io.ObjectInput
java.io.ObjectInputStream
java.io.ObjectInputStream$GetField
java.io.ObjectInputStream$InputValidationDesc
java.io.ObjectInputValidation
java.io.ObjectOutput
java.io.ObjectOutputStream
java.io.ObjectOutputStream$PutField
java.io.ObjectStreamClass
java.io.ObjectStreamClass$1
java.io.ObjectStreamClass$2
java.io.ObjectStreamClass$3
java.io.ObjectStreamClass$4
java.io.ObjectStreamClass$5
java.io.ObjectStreamClass$Digest
java.io.ObjectStreamConstants
java.io.ObjectStreamException
java.io.ObjectStreamField
java.io.OptionalDataException
java.io.OutputStream
java.io.OutputStreamWriter
java.io.PipedInputStream
java.io.PipedOutputStream
java.io.PipedReader
java.io.PipedWriter
java.io.PrintStream
java.io.PrintWriter
java.io.PushbackInputStream
java.io.PushbackReader
java.io.RandomAccessFile
java.io.Reader
java.io.SequenceInputStream
java.io.SerialVersionUIDDigest
java.io.Serializable
java.io.SerializablePermission
java.io.SerializationHandleMap
java.io.StreamCorruptedException
java.io.StreamTokenizer
java.io.StringBufferInputStream
java.io.StringReader
java.io.StringWriter
java.io.SyncFailedException
java.io.UTFDataFormatException
java.io.UncheckedIOException
java.io.UnsupportedEncodingException
java.io.WriteAbortedException
java.io.Writer
java.lang.AbstractMethodError
java.lang.AbstractStringBuilder
java.lang.Appendable
java.lang.ArithmeticException
java.lang.ArrayIndexOutOfBoundsException
java.lang.ArrayStoreException
java.lang.AssertionError
java.lang.AutoCloseable
java.lang.Boolean
java.lang.Byte
java.lang.Byte$ByteCache
java.lang.CharSequence
java.lang.CharSequence$1CharIterator
java.lang.CharSequence$1CodePointIterator
java.lang.Character
java.lang.Character$CharacterCache
java.lang.Character$Subset
java.lang.Character$UnicodeBlock
java.lang.Character$UnicodeScript
java.lang.Class
java.lang.ClassCastException
java.lang.ClassCircularityError
java.lang.ClassFormatError
java.lang.ClassLoader
java.lang.ClassNotFoundException
java.lang.CloneNotSupportedException
java.lang.Cloneable
java.lang.Comparable
java.lang.Deprecated
java.lang.Double
java.lang.Enum
java.lang.Enum$1
java.lang.EnumConstantNotPresentException
java.lang.Error
java.lang.Exception
java.lang.ExceptionInInitializerError
java.lang.Float
java.lang.FunctionalInterface
java.lang.IllegalAccessError
java.lang.IllegalAccessException
java.lang.IllegalArgumentException
java.lang.IllegalMonitorStateException
java.lang.IllegalStateException
java.lang.IllegalThreadStateException
java.lang.IncompatibleClassChangeError
java.lang.IndexOutOfBoundsException
java.lang.InheritableThreadLocal
java.lang.InstantiationError
java.lang.InstantiationException
java.lang.Integer
java.lang.Integer$IntegerCache
java.lang.InternalError
java.lang.InterruptedException
java.lang.Iterable
java.lang.JavaLangAccess
java.lang.LinkageError
java.lang.Long
java.lang.Long$LongCache
java.lang.Math
java.lang.Math$NoImagePreloadHolder
java.lang.NSException
java.lang.NegativeArraySizeException
java.lang.NoClassDefFoundError
java.lang.NoSuchFieldError
java.lang.NoSuchFieldException
java.lang.NoSuchMethodError
java.lang.NoSuchMethodException
java.lang.NullPointerException
java.lang.Number
java.lang.NumberFormatException
java.lang.Object:
    148:148:public final java.lang.Class getClass()
    168:168:public int hashCode()
    196:196:public boolean equals(java.lang.Object)
    215:215:protected java.lang.Object clone()
    232:232:public java.lang.String toString()
    263:263:protected void finalize()
    290:290:public final void notify()
    318:318:public final void notifyAll()
    355:355:public final void wait(long)
    396:396:public final void wait(long,int)
    425:425:public final void wait()
java.lang.OutOfMemoryError
java.lang.Override
java.lang.Package
java.lang.Package$1PackageInfoProxy
java.lang.Readable
java.lang.ReflectiveOperationException
java.lang.Runnable
java.lang.Runtime
java.lang.RuntimeException
java.lang.RuntimePermission
java.lang.SafeVarargs
java.lang.SecurityException
java.lang.SecurityManager
java.lang.Short
java.lang.Short$ShortCache
java.lang.StackOverflowError
java.lang.StackTraceElement
java.lang.StrictMath
java.lang.String
java.lang.String$1
java.lang.String$CaseInsensitiveComparator
java.lang.StringBuffer
java.lang.StringBuilder
java.lang.StringIndexOutOfBoundsException
java.lang.SuppressWarnings
java.lang.System
java.lang.SystemClassLoader
java.lang.Thread
java.lang.Thread$1
java.lang.Thread$ParkState
java.lang.Thread$State
java.lang.Thread$SystemUncaughtExceptionHandler
java.lang.Thread$UncaughtExceptionHandler
java.lang.ThreadDeath
java.lang.ThreadGroup
java.lang.ThreadLocal
java.lang.ThreadLocal$1
java.lang.ThreadLocal$ThreadLocalMap
java.lang.ThreadLocal$ThreadLocalMap$Entry
java.lang.Throwable
java.lang.Throwable$1
java.lang.Throwable$PrintStreamOrWriter
java.lang.Throwable$SentinelHolder
java.lang.Throwable$WrappedPrintStream
java.lang.Throwable$WrappedPrintWriter
java.lang.TypeNotPresentException
java.lang.UnknownError
java.lang.UnsatisfiedLinkError
java.lang.UnsupportedClassVersionError
java.lang.UnsupportedOperationException
java.lang.VirtualMachineError
java.lang.Void
java.lang.annotation.Annotation
java.lang.annotation.AnnotationFormatError
java.lang.annotation.AnnotationTypeMismatchException
java.lang.annotation.Documented
java.lang.annotation.ElementType
java.lang.annotation.IncompleteAnnotationException
java.lang.annotation.Inherited
java.lang.annotation.Native
java.lang.annotation.Repeatable
java.lang.annotation.Retention
java.lang.annotation.RetentionPolicy
java.lang.annotation.Target
java.lang.invoke.CallSite
java.lang.invoke.LambdaConversionException
java.lang.invoke.LambdaMetafactory
java.lang.invoke.MethodHandle
java.lang.invoke.MethodHandleInfo
java.lang.invoke.MethodHandles
java.lang.invoke.MethodHandles$Lookup
java.lang.invoke.MethodType
java.lang.invoke.SerializedLambda
java.lang.ref.PhantomReference
java.lang.ref.Reference
java.lang.ref.ReferenceQueue
java.lang.ref.SoftReference
java.lang.ref.WeakReference
java.lang.reflect.AccessibleObject
java.lang.reflect.AnnotatedElement
java.lang.reflect.AnnotatedType
java.lang.reflect.Array
java.lang.reflect.Constructor
java.lang.reflect.Executable
java.lang.reflect.Field
java.lang.reflect.GenericArrayType
java.lang.reflect.GenericDeclaration
java.lang.reflect.GenericSignatureFormatError
java.lang.reflect.InvocationHandler
java.lang.reflect.InvocationTargetException
java.lang.reflect.MalformedParameterizedTypeException
java.lang.reflect.Member
java.lang.reflect.Method
java.lang.reflect.Modifier
java.lang.reflect.Parameter
java.lang.reflect.ParameterizedType
java.lang.reflect.Proxy
java.lang.reflect.Proxy$1
java.lang.reflect.Proxy$ThreadLocalBoolean
java.lang.reflect.ReflectPermission
java.lang.reflect.Type
java.lang.reflect.TypeVariable
java.lang.reflect.UndeclaredThrowableException
java.lang.reflect.WildcardType
java.math.BigDecimal
java.math.BigDecimal$1
java.math.BigDecimal$LongOverflow
java.math.BigDecimal$StringBuilderHelper
java.math.BigDecimal$UnsafeHolder
java.math.BigInteger
java.math.BigInteger$UnsafeHolder
java.math.BitSieve
java.math.MathContext
java.math.MutableBigInteger
java.math.RoundingMode
java.math.SignedMutableBigInteger
java.net.AbstractPlainDatagramSocketImpl
java.net.AbstractPlainSocketImpl
java.net.AddressCache
java.net.AddressCache$AddressCacheEntry
java.net.AddressCache$AddressCacheKey
java.net.Authenticator
java.net.Authenticator$RequestorType
java.net.BindException
java.net.CacheRequest
java.net.CacheResponse
java.net.ConnectException
java.net.ContentHandler
java.net.ContentHandlerFactory
java.net.CookieHandler
java.net.CookieManager
java.net.CookieManager$CookiePathComparator
java.net.CookiePolicy
java.net.CookiePolicy$1
java.net.CookiePolicy$2
java.net.CookiePolicy$3
java.net.CookieStore
java.net.DatagramPacket
java.net.DatagramSocket
java.net.DatagramSocketImpl
java.net.DatagramSocketImplFactory
java.net.DefaultDatagramSocketImplFactory
java.net.DefaultFileNameMap
java.net.DefaultInterface
java.net.FileNameMap
java.net.HttpCookie
java.net.HttpCookie$1
java.net.HttpCookie$10
java.net.HttpCookie$11
java.net.HttpCookie$2
java.net.HttpCookie$3
java.net.HttpCookie$4
java.net.HttpCookie$5
java.net.HttpCookie$6
java.net.HttpCookie$7
java.net.HttpCookie$8
java.net.HttpCookie$9
java.net.HttpCookie$CookieAttributeAssignor
java.net.HttpRetryException
java.net.HttpURLConnection
java.net.IDN
java.net.InMemoryCookieStore
java.net.Inet4Address
java.net.Inet6Address
java.net.Inet6AddressImpl
java.net.InetAddress
java.net.InetAddress$1
java.net.InetAddress$InetAddressHolder
java.net.InetAddressContainer
java.net.InetAddressImpl
java.net.InetSocketAddress
java.net.InetSocketAddress$1
java.net.InetSocketAddress$InetSocketAddressHolder
java.net.InterfaceAddress
java.net.JarURLConnection
java.net.MalformedURLException
java.net.MulticastSocket
java.net.NetFactory
java.net.NetFactory$FactoryInterface
java.net.NetFactoryImpl
java.net.NetPermission
java.net.NetUtil
java.net.NetworkInterface
java.net.NetworkInterface$1
java.net.NetworkInterface$1checkedAddresses
java.net.NetworkInterface$1subIFs
java.net.NoRouteToHostException
java.net.Parts
java.net.PasswordAuthentication
java.net.PlainDatagramSocketImpl
java.net.PlainServerSocketImpl
java.net.PlainSocketImpl
java.net.PortUnreachableException
java.net.ProtocolException
java.net.ProtocolFamily
java.net.Proxy
java.net.Proxy$Type
java.net.ProxySelector
java.net.ProxySelectorImpl
java.net.ResponseCache
java.net.SecureCacheResponse
java.net.ServerSocket
java.net.Socket
java.net.SocketAddress
java.net.SocketException
java.net.SocketImpl
java.net.SocketImplFactory
java.net.SocketInputStream
java.net.SocketOption
java.net.SocketOptions
java.net.SocketOutputStream
java.net.SocketPermission
java.net.SocketTimeoutException
java.net.Socks4Message
java.net.SocksConsts
java.net.SocksSocketImpl
java.net.StandardProtocolFamily
java.net.StandardSocketOptions
java.net.StandardSocketOptions$StdSocketOption
java.net.URI
java.net.URI$Parser
java.net.URISyntaxException
java.net.URL
java.net.URLClassLoader
java.net.URLConnection
java.net.URLDecoder
java.net.URLEncoder
java.net.URLStreamHandler
java.net.URLStreamHandlerFactory
java.net.UnknownContentHandler
java.net.UnknownHostException
java.net.UnknownServiceException
java.nio.Bits
java.nio.Buffer
java.nio.BufferOverflowException
java.nio.BufferUnderflowException
java.nio.ByteBuffer
java.nio.ByteBufferAsCharBuffer
java.nio.ByteBufferAsDoubleBuffer
java.nio.ByteBufferAsFloatBuffer
java.nio.ByteBufferAsIntBuffer
java.nio.ByteBufferAsLongBuffer
java.nio.ByteBufferAsShortBuffer
java.nio.ByteOrder
java.nio.ChannelFactoryImpl
java.nio.CharBuffer
java.nio.CharBufferSpliterator
java.nio.DirectByteBuffer
java.nio.DirectByteBuffer$MemoryRef
java.nio.DoubleBuffer
java.nio.FloatBuffer
java.nio.HeapByteBuffer
java.nio.HeapCharBuffer
java.nio.HeapDoubleBuffer
java.nio.HeapFloatBuffer
java.nio.HeapIntBuffer
java.nio.HeapLongBuffer
java.nio.HeapShortBuffer
java.nio.IntBuffer
java.nio.InvalidMarkException
java.nio.LongBuffer
java.nio.MappedByteBuffer
java.nio.NioUtils
java.nio.NioUtils$ChannelFactory
java.nio.ReadOnlyBufferException
java.nio.ShortBuffer
java.nio.StringCharBuffer
java.nio.channels.AlreadyBoundException
java.nio.channels.AlreadyConnectedException
java.nio.channels.AsynchronousCloseException
java.nio.channels.ByteChannel
java.nio.channels.CancelledKeyException
java.nio.channels.Channel
java.nio.channels.Channels
java.nio.channels.Channels$1
java.nio.channels.Channels$ReadableByteChannelImpl
java.nio.channels.Channels$WritableByteChannelImpl
java.nio.channels.ClosedByInterruptException
java.nio.channels.ClosedChannelException
java.nio.channels.ClosedSelectorException
java.nio.channels.ConnectionPendingException
java.nio.channels.DatagramChannel
java.nio.channels.FileChannel
java.nio.channels.FileChannel$MapMode
java.nio.channels.FileLock
java.nio.channels.FileLockInterruptionException
java.nio.channels.GatheringByteChannel
java.nio.channels.IllegalBlockingModeException
java.nio.channels.IllegalSelectorException
java.nio.channels.InterruptibleChannel
java.nio.channels.NetworkChannel
java.nio.channels.NoConnectionPendingException
java.nio.channels.NonReadableChannelException
java.nio.channels.NonWritableChannelException
java.nio.channels.NotYetBoundException
java.nio.channels.NotYetConnectedException
java.nio.channels.OverlappingFileLockException
java.nio.channels.Pipe
java.nio.channels.Pipe$SinkChannel
java.nio.channels.Pipe$SourceChannel
java.nio.channels.ReadableByteChannel
java.nio.channels.ScatteringByteChannel
java.nio.channels.SeekableByteChannel
java.nio.channels.SelectableChannel
java.nio.channels.SelectionKey
java.nio.channels.Selector
java.nio.channels.ServerSocketChannel
java.nio.channels.SocketChannel
java.nio.channels.UnresolvedAddressException
java.nio.channels.UnsupportedAddressTypeException
java.nio.channels.WritableByteChannel
java.nio.channels.spi.AbstractInterruptibleChannel
java.nio.channels.spi.AbstractInterruptibleChannel$1
java.nio.channels.spi.AbstractInterruptibleChannel$Interruptor
java.nio.channels.spi.AbstractSelectableChannel
java.nio.channels.spi.AbstractSelectionKey
java.nio.channels.spi.AbstractSelector
java.nio.channels.spi.AbstractSelector$1
java.nio.channels.spi.AbstractSelector$WeakUpTask
java.nio.channels.spi.SelectorProvider
java.nio.charset.CharacterCodingException
java.nio.charset.Charset
java.nio.charset.CharsetDecoder
java.nio.charset.CharsetEncoder
java.nio.charset.Charsets
java.nio.charset.CoderMalfunctionError
java.nio.charset.CoderResult
java.nio.charset.CodingErrorAction
java.nio.charset.IllegalCharsetNameException
java.nio.charset.MalformedInputException
java.nio.charset.ModifiedUtf8
java.nio.charset.StandardCharsets
java.nio.charset.UnmappableCharacterException
java.nio.charset.UnsupportedCharsetException
java.nio.charset.spi.CharsetProvider
java.security.AccessControlContext
java.security.AccessControlException
java.security.AccessController
java.security.AlgorithmConstraints
java.security.AlgorithmParameterGenerator
java.security.AlgorithmParameterGeneratorSpi
java.security.AlgorithmParameters
java.security.AlgorithmParametersSpi
java.security.AllPermission
java.security.BasicPermission
java.security.CodeSigner
java.security.CodeSource
java.security.CryptoPrimitive
java.security.DigestException
java.security.DigestInputStream
java.security.DigestOutputStream
java.security.DomainCombiner
java.security.GeneralSecurityException
java.security.Guard
java.security.GuardedObject
java.security.InvalidAlgorithmParameterException
java.security.InvalidKeyException
java.security.InvalidParameterException
java.security.Key
java.security.KeyException
java.security.KeyFactory
java.security.KeyFactorySpi
java.security.KeyManagementException
java.security.KeyPair
java.security.KeyPairGenerator
java.security.KeyPairGenerator$Delegate
java.security.KeyPairGeneratorSpi
java.security.KeyRep
java.security.KeyRep$Type
java.security.KeyStore
java.security.KeyStore$1
java.security.KeyStore$Builder
java.security.KeyStore$Builder$1
java.security.KeyStore$Builder$2
java.security.KeyStore$Builder$2$PrivAction
java.security.KeyStore$Builder$FileBuilder
java.security.KeyStore$Builder$FileBuilder$1
java.security.KeyStore$CallbackHandlerProtection
java.security.KeyStore$Entry
java.security.KeyStore$LoadStoreParameter
java.security.KeyStore$PasswordProtection
java.security.KeyStore$PrivateKeyEntry
java.security.KeyStore$ProtectionParameter
java.security.KeyStore$SecretKeyEntry
java.security.KeyStore$SimpleLoadStoreParameter
java.security.KeyStore$TrustedCertificateEntry
java.security.KeyStoreException
java.security.KeyStoreSpi
java.security.MessageDigest
java.security.MessageDigest$Delegate
java.security.MessageDigestSpi
java.security.NoSuchAlgorithmException
java.security.NoSuchProviderException
java.security.Permission
java.security.PermissionCollection
java.security.Permissions
java.security.Policy
java.security.Policy$Parameters
java.security.Policy$UnsupportedEmptyCollection
java.security.Principal
java.security.PrivateKey
java.security.PrivilegedAction
java.security.PrivilegedActionException
java.security.PrivilegedExceptionAction
java.security.ProtectionDomain
java.security.Provider
java.security.Provider$1
java.security.Provider$EngineDescription
java.security.Provider$Service
java.security.Provider$ServiceKey
java.security.Provider$UString
java.security.ProviderException
java.security.PublicKey
java.security.SecureClassLoader
java.security.SecureRandom
java.security.SecureRandomSpi
java.security.Security
java.security.Security$1
java.security.Security$ProviderProperty
java.security.SecurityPermission
java.security.Signature
java.security.Signature$CipherAdapter
java.security.Signature$Delegate
java.security.SignatureException
java.security.SignatureSpi
java.security.Timestamp
java.security.UnrecoverableEntryException
java.security.UnrecoverableKeyException
java.security.cert.CRL
java.security.cert.CRLException
java.security.cert.CRLReason
java.security.cert.CRLSelector
java.security.cert.CertPath
java.security.cert.CertPath$CertPathRep
java.security.cert.CertPathBuilder
java.security.cert.CertPathBuilder$1
java.security.cert.CertPathBuilderException
java.security.cert.CertPathBuilderResult
java.security.cert.CertPathBuilderSpi
java.security.cert.CertPathChecker
java.security.cert.CertPathHelperImpl
java.security.cert.CertPathParameters
java.security.cert.CertPathValidator
java.security.cert.CertPathValidator$1
java.security.cert.CertPathValidatorException
java.security.cert.CertPathValidatorException$BasicReason
java.security.cert.CertPathValidatorException$Reason
java.security.cert.CertPathValidatorResult
java.security.cert.CertPathValidatorSpi
java.security.cert.CertSelector
java.security.cert.CertStore
java.security.cert.CertStore$1
java.security.cert.CertStoreException
java.security.cert.CertStoreParameters
java.security.cert.CertStoreSpi
java.security.cert.Certificate
java.security.cert.Certificate$CertificateRep
java.security.cert.CertificateEncodingException
java.security.cert.CertificateException
java.security.cert.CertificateExpiredException
java.security.cert.CertificateFactory
java.security.cert.CertificateFactorySpi
java.security.cert.CertificateNotYetValidException
java.security.cert.CertificateParsingException
java.security.cert.CertificateRevokedException
java.security.cert.CollectionCertStoreParameters
java.security.cert.Extension
java.security.cert.LDAPCertStoreParameters
java.security.cert.PKIXBuilderParameters
java.security.cert.PKIXCertPathBuilderResult
java.security.cert.PKIXCertPathChecker
java.security.cert.PKIXCertPathValidatorResult
java.security.cert.PKIXParameters
java.security.cert.PKIXReason
java.security.cert.PKIXRevocationChecker
java.security.cert.PKIXRevocationChecker$Option
java.security.cert.PolicyNode
java.security.cert.PolicyQualifierInfo
java.security.cert.TrustAnchor
java.security.cert.X509CRL
java.security.cert.X509CRLEntry
java.security.cert.X509CRLSelector
java.security.cert.X509CertSelector
java.security.cert.X509Certificate
java.security.cert.X509Extension
java.security.interfaces.DSAKey
java.security.interfaces.DSAParams
java.security.interfaces.DSAPrivateKey
java.security.interfaces.DSAPublicKey
java.security.interfaces.ECKey
java.security.interfaces.ECPrivateKey
java.security.interfaces.ECPublicKey
java.security.interfaces.RSAKey
java.security.interfaces.RSAMultiPrimePrivateCrtKey
java.security.interfaces.RSAPrivateCrtKey
java.security.interfaces.RSAPrivateKey
java.security.interfaces.RSAPublicKey
java.security.spec.AlgorithmParameterSpec
java.security.spec.DSAParameterSpec
java.security.spec.DSAPrivateKeySpec
java.security.spec.DSAPublicKeySpec
java.security.spec.ECField
java.security.spec.ECFieldF2m
java.security.spec.ECFieldFp
java.security.spec.ECGenParameterSpec
java.security.spec.ECParameterSpec
java.security.spec.ECPoint
java.security.spec.ECPrivateKeySpec
java.security.spec.ECPublicKeySpec
java.security.spec.EllipticCurve
java.security.spec.EncodedKeySpec
java.security.spec.InvalidKeySpecException
java.security.spec.InvalidParameterSpecException
java.security.spec.KeySpec
java.security.spec.MGF1ParameterSpec
java.security.spec.PKCS8EncodedKeySpec
java.security.spec.PSSParameterSpec
java.security.spec.RSAKeyGenParameterSpec
java.security.spec.RSAMultiPrimePrivateCrtKeySpec
java.security.spec.RSAOtherPrimeInfo
java.security.spec.RSAPrivateCrtKeySpec
java.security.spec.RSAPrivateKeySpec
java.security.spec.RSAPublicKeySpec
java.security.spec.X509EncodedKeySpec
java.sql.Array
java.sql.BatchUpdateException
java.sql.Blob
java.sql.CallableStatement
java.sql.ClientInfoStatus
java.sql.Clob
java.sql.Connection
java.sql.DataTruncation
java.sql.DatabaseMetaData
java.sql.Date
java.sql.Driver
java.sql.DriverInfo
java.sql.DriverManager
java.sql.DriverPropertyInfo
java.sql.NClob
java.sql.ParameterMetaData
java.sql.PreparedStatement
java.sql.Ref
java.sql.ResultSet
java.sql.ResultSetMetaData
java.sql.RowId
java.sql.RowIdLifetime
java.sql.SQLClientInfoException
java.sql.SQLData
java.sql.SQLDataException
java.sql.SQLException
java.sql.SQLException$1
java.sql.SQLException$NextExceptionUpdater
java.sql.SQLFeatureNotSupportedException
java.sql.SQLInput
java.sql.SQLIntegrityConstraintViolationException
java.sql.SQLInvalidAuthorizationSpecException
java.sql.SQLNonTransientConnectionException
java.sql.SQLNonTransientException
java.sql.SQLOutput
java.sql.SQLPermission
java.sql.SQLRecoverableException
java.sql.SQLSyntaxErrorException
java.sql.SQLTimeoutException
java.sql.SQLTransactionRollbackException
java.sql.SQLTransientConnectionException
java.sql.SQLTransientException
java.sql.SQLWarning
java.sql.SQLXML
java.sql.Savepoint
java.sql.Statement
java.sql.Struct
java.sql.Time
java.sql.Timestamp
java.sql.Types
java.sql.Wrapper
java.text.Annotation
java.text.AttributeEntry
java.text.AttributedCharacterIterator
java.text.AttributedCharacterIterator$Attribute
java.text.AttributedString
java.text.AttributedString$AttributeMap
java.text.AttributedString$AttributedStringIterator
java.text.CalendarBuilder
java.text.CharacterIterator
java.text.CharacterIteratorFieldDelegate
java.text.ChoiceFormat
java.text.CollationKey
java.text.Collator
java.text.DateFormat
java.text.DateFormat$Field
java.text.DateFormatSymbols
java.text.DecimalFormat
java.text.DecimalFormat$1
java.text.DecimalFormat$DigitArrays
java.text.DecimalFormat$FastPathData
java.text.DecimalFormatSymbols
java.text.DigitList
java.text.DigitList$1
java.text.DontCareFieldPosition
java.text.DontCareFieldPosition$1
java.text.FieldPosition
java.text.FieldPosition$1
java.text.FieldPosition$Delegate
java.text.Format
java.text.Format$Field
java.text.Format$FieldDelegate
java.text.IOSCollator
java.text.IOSCollator$IOSCollationKey
java.text.MessageFormat
java.text.MessageFormat$Field
java.text.Normalizer
java.text.Normalizer$1
java.text.Normalizer$Form
java.text.NumberFormat
java.text.NumberFormat$Field
java.text.ParseException
java.text.ParsePosition
java.text.SimpleDateFormat
java.text.StringCharacterIterator
java.util.AbstractCollection:
    private static final int MAX_ARRAY_SIZE
    public abstract java.util.Iterator iterator()
    public abstract int size()
    86:86:public boolean isEmpty()
    99:109:public boolean contains(java.lang.Object)
    public native java.lang.Object[] toArray()
    public native java.lang.Object[] toArray(java.lang.Object[])
    198:211:private static java.lang.Object[] finishToArray(java.lang.Object[],java.util.Iterator)
    215:220:private static int hugeCapacity(int)
    238:238:public boolean add(java.lang.Object)
    258:274:public boolean remove(java.lang.Object)
    293:296:public boolean containsAll(java.util.Collection)
    318:322:public boolean addAll(java.util.Collection)
    347:355:public boolean removeAll(java.util.Collection)
    380:388:public boolean retainAll(java.util.Collection)
    407:412:public void clear()
    428:440:public java.lang.String toString()
java.util.AbstractList:
    108:109:public boolean add(java.lang.Object)
    public abstract java.lang.Object get(int)
    132:132:public java.lang.Object set(int,java.lang.Object)
    148:148:public void add(int,java.lang.Object)
    161:161:public java.lang.Object remove(int)
    178:188:public int indexOf(java.lang.Object)
    203:213:public int lastIndexOf(java.lang.Object)
    234:235:public void clear()
    257:263:public boolean addAll(int,java.util.Collection)
    288:288:public java.util.Iterator iterator()
    299:299:public java.util.ListIterator listIterator()
    325:327:public java.util.ListIterator listIterator(int)
    484:486:public java.util.List subList(int,int)
    513:526:public boolean equals(java.lang.Object)
    539:542:public int hashCode()
    568:573:protected void removeRange(int,int)
    604:606:private void rangeCheckForAdd(int)
    609:609:private java.lang.String outOfBoundsMsg(int)
java.util.AbstractList$1
java.util.AbstractList$Itr
java.util.AbstractList$ListItr
java.util.AbstractMap:
    91:91:public int size()
    100:100:public boolean isEmpty()
    116:130:public boolean containsValue(java.lang.Object)
    147:161:public boolean containsKey(java.lang.Object)
    178:192:public java.lang.Object get(java.lang.Object)
    210:210:public java.lang.Object put(java.lang.Object,java.lang.Object)
    235:256:public java.lang.Object remove(java.lang.Object)
    279:281:public void putAll(java.util.Map)
    295:296:public void clear()
    325:366:public java.util.Set keySet()
    385:426:public java.util.Collection values()
    public abstract java.util.Set entrySet()
    456:485:public boolean equals(java.lang.Object)
    506:510:public int hashCode()
    526:542:public java.lang.String toString()
    552:555:protected java.lang.Object clone()
    563:563:private static boolean eq(java.lang.Object,java.lang.Object)
    75:75:static synthetic boolean access$000(java.lang.Object,java.lang.Object)
java.util.AbstractMap$1AbstractMapKeySet
java.util.AbstractMap$1AbstractMapKeySet$1
java.util.AbstractMap$1AbstractMapValuesCollection
java.util.AbstractMap$1AbstractMapValuesCollection$1
java.util.AbstractMap$SimpleEntry
java.util.AbstractMap$SimpleImmutableEntry
java.util.AbstractQueue
java.util.AbstractSequentialList
java.util.AbstractSet:
    86:99:public boolean equals(java.lang.Object)
    121:128:public int hashCode()
    169:182:public boolean removeAll(java.util.Collection)
java.util.ArrayDeque
java.util.ArrayDeque$1
java.util.ArrayDeque$DeqIterator
java.util.ArrayDeque$DeqSpliterator
java.util.ArrayDeque$DescendingIterator
java.util.ArrayList
java.util.ArrayList$1
java.util.ArrayList$ArrayListSpliterator
java.util.ArrayList$Itr
java.util.ArrayList$ListItr
java.util.ArrayList$SubList
java.util.ArrayList$SubList$1
java.util.ArrayPrefixHelpers
java.util.ArrayPrefixHelpers$CumulateTask
java.util.ArrayPrefixHelpers$DoubleCumulateTask
java.util.ArrayPrefixHelpers$IntCumulateTask
java.util.ArrayPrefixHelpers$LongCumulateTask
java.util.Arrays
java.util.Arrays$ArrayList
java.util.Arrays$LegacyMergeSort
java.util.Arrays$NaturalOrder
java.util.ArraysParallelSortHelpers
java.util.ArraysParallelSortHelpers$EmptyCompleter
java.util.ArraysParallelSortHelpers$FJByte
java.util.ArraysParallelSortHelpers$FJByte$Merger
java.util.ArraysParallelSortHelpers$FJByte$Sorter
java.util.ArraysParallelSortHelpers$FJChar
java.util.ArraysParallelSortHelpers$FJChar$Merger
java.util.ArraysParallelSortHelpers$FJChar$Sorter
java.util.ArraysParallelSortHelpers$FJDouble
java.util.ArraysParallelSortHelpers$FJDouble$Merger
java.util.ArraysParallelSortHelpers$FJDouble$Sorter
java.util.ArraysParallelSortHelpers$FJFloat
java.util.ArraysParallelSortHelpers$FJFloat$Merger
java.util.ArraysParallelSortHelpers$FJFloat$Sorter
java.util.ArraysParallelSortHelpers$FJInt
java.util.ArraysParallelSortHelpers$FJInt$Merger
java.util.ArraysParallelSortHelpers$FJInt$Sorter
java.util.ArraysParallelSortHelpers$FJLong
java.util.ArraysParallelSortHelpers$FJLong$Merger
java.util.ArraysParallelSortHelpers$FJLong$Sorter
java.util.ArraysParallelSortHelpers$FJObject
java.util.ArraysParallelSortHelpers$FJObject$Merger
java.util.ArraysParallelSortHelpers$FJObject$Sorter
java.util.ArraysParallelSortHelpers$FJShort
java.util.ArraysParallelSortHelpers$FJShort$Merger
java.util.ArraysParallelSortHelpers$FJShort$Sorter
java.util.ArraysParallelSortHelpers$Relay
java.util.Base64
java.util.Base64$1
java.util.Base64$DecInputStream
java.util.Base64$Decoder
java.util.Base64$EncOutputStream
java.util.Base64$Encoder
java.util.BitSet
java.util.BitSet$1BitSetIterator
java.util.Calendar
java.util.Collection:
    public abstract int size()
    public abstract boolean isEmpty()
    public abstract boolean contains(java.lang.Object)
    public abstract java.util.Iterator iterator()
    public abstract java.lang.Object[] toArray()
    public abstract java.lang.Object[] toArray(java.lang.Object[])
    public abstract boolean add(java.lang.Object)
    public abstract boolean remove(java.lang.Object)
    public abstract boolean containsAll(java.util.Collection)
    public abstract boolean addAll(java.util.Collection)
    public abstract boolean removeAll(java.util.Collection)
    397:406:public boolean removeIf(java.util.function.Predicate)
    public abstract boolean retainAll(java.util.Collection)
    public abstract void clear()
    public abstract boolean equals(java.lang.Object)
    public abstract int hashCode()
    549:549:public java.util.Spliterator spliterator()
    568:568:public java.util.stream.Stream stream()
    589:589:public java.util.stream.Stream parallelStream()
java.util.Collections:
    private static final int BINARYSEARCH_THRESHOLD
    private static final int REVERSE_THRESHOLD
    private static final int SHUFFLE_THRESHOLD
    private static final int FILL_THRESHOLD
    private static final int ROTATE_THRESHOLD
    private static final int COPY_THRESHOLD
    private static final int REPLACEALL_THRESHOLD
    private static final int INDEXOFSUBLIST_THRESHOLD
    private static java.util.Random r
    168:180:public static void sort(java.util.List)
    237:249:public static void sort(java.util.List,java.util.Comparator)
    285:288:public static int binarySearch(java.util.List,java.lang.Object)
    293:308:private static int indexedBinarySearch(java.util.List,java.lang.Object)
    314:330:private static int iteratorBinarySearch(java.util.List,java.lang.Object)
    338:349:private static java.lang.Object get(java.util.ListIterator,int)
    389:395:public static int binarySearch(java.util.List,java.lang.Object,java.util.Comparator)
    399:414:private static int indexedBinarySearch(java.util.List,java.lang.Object,java.util.Comparator)
    418:434:private static int iteratorBinarySearch(java.util.List,java.lang.Object,java.util.Comparator)
    448:464:public static void reverse(java.util.List)
    495:499:public static void shuffle(java.util.List)
    528:549:public static void shuffle(java.util.List,java.util.Random)
    569:571:public static void swap(java.util.List,int,int)
    577:580:private static void swap(java.lang.Object[],int,int)
    595:607:public static void fill(java.util.List,java.lang.Object)
    627:643:public static void copy(java.util.List,java.util.List)
    668:676:public static java.lang.Object min(java.util.Collection)
    704:715:public static java.lang.Object min(java.util.Collection,java.util.Comparator)
    741:749:public static java.lang.Object max(java.util.Collection)
    777:788:public static java.lang.Object max(java.util.Collection,java.util.Comparator)
    847:851:public static void rotate(java.util.List,int)
    854:874:private static void rotate1(java.util.List,int)
    877:889:private static void rotate2(java.util.List,int)
    911:947:public static boolean replaceAll(java.util.List,java.lang.Object,java.lang.Object)
    971:1000:public static int indexOfSubList(java.util.List,java.util.List)
    1024:1057:public static int lastIndexOfSubList(java.util.List,java.util.List)
    1086:1086:public static java.util.Collection unmodifiableCollection(java.util.Collection)
    1193:1193:public static java.util.Set unmodifiableSet(java.util.Set)
    1226:1226:public static java.util.SortedSet unmodifiableSortedSet(java.util.SortedSet)
    1273:1275:public static java.util.List unmodifiableList(java.util.List)
    1417:1417:public static java.util.Map unmodifiableMap(java.util.Map)
    1772:1772:public static java.util.SortedMap unmodifiableSortedMap(java.util.SortedMap)
    1833:1833:public static java.util.Collection synchronizedCollection(java.util.Collection)
    1837:1837:static java.util.Collection synchronizedCollection(java.util.Collection,java.lang.Object)
    1957:1957:public static java.util.Set synchronizedSet(java.util.Set)
    1961:1961:static java.util.Set synchronizedSet(java.util.Set,java.lang.Object)
    2028:2028:public static java.util.SortedSet synchronizedSortedSet(java.util.SortedSet)
    2107:2109:public static java.util.List synchronizedList(java.util.List)
    2113:2115:static java.util.List synchronizedList(java.util.List,java.lang.Object)
    2278:2278:public static java.util.Map synchronizedMap(java.util.Map)
    2470:2470:public static java.util.SortedMap synchronizedSortedMap(java.util.SortedMap)
    2587:2587:public static java.util.Collection checkedCollection(java.util.Collection,java.lang.Class)
    2592:2592:static java.lang.Object[] zeroLengthArray(java.lang.Class)
    2738:2738:public static java.util.Set checkedSet(java.util.Set,java.lang.Class)
    2785:2785:public static java.util.SortedSet checkedSortedSet(java.util.SortedSet,java.lang.Class)
    2846:2848:public static java.util.List checkedList(java.util.List,java.lang.Class)
    3005:3005:public static java.util.Map checkedMap(java.util.Map,java.lang.Class,java.lang.Class)
    3402:3402:public static java.util.SortedMap checkedSortedMap(java.util.SortedMap,java.lang.Class,java.lang.Class)
    3460:3460:public static java.util.Iterator emptyIterator()
    3504:3504:public static java.util.ListIterator emptyListIterator()
    3541:3541:public static java.util.Enumeration emptyEnumeration()
    3581:3581:public static final java.util.Set emptySet()
    3657:3657:public static final java.util.List emptyList()
    3758:3758:public static final java.util.Map emptyMap()
    3867:3867:static java.util.Iterator singletonIterator(java.lang.Object)
    3900:3900:static java.util.Spliterator singletonSpliterator(java.lang.Object)
    3985:3985:public static java.util.List singletonList(java.lang.Object)
    4049:4049:public static java.util.Map singletonMap(java.lang.Object,java.lang.Object)
    4182:4184:public static java.util.List nCopies(int,java.lang.Object)
    4301:4301:public static java.util.Comparator reverseOrder()
    4345:4351:public static java.util.Comparator reverseOrder(java.util.Comparator)
    4407:4407:public static java.util.Enumeration enumeration(java.util.Collection)
    4437:4440:public static java.util.ArrayList list(java.util.Enumeration)
    4449:4449:static boolean eq(java.lang.Object,java.lang.Object)
    4466:4476:public static int frequency(java.util.Collection,java.lang.Object)
    4520:4566:public static boolean disjoint(java.util.Collection,java.util.Collection)
    4598:4601:public static varargs boolean addAll(java.util.Collection,java.lang.Object[])
    4636:4636:public static java.util.Set newSetFromMap(java.util.Map)
    4718:4718:public static java.util.Queue asLifoQueue(java.util.Deque)
java.util.Collections$1:
    private boolean hasNext
    final synthetic java.lang.Object val$e
    3867:3868:Collections$1(java.lang.Object)
    3870:3870:public boolean hasNext()
    3873:3877:public java.lang.Object next()
    3880:3880:public void remove()
    3884:3889:public void forEachRemaining(java.util.function.Consumer)
java.util.Collections$2
java.util.Collections$3
java.util.Collections$AsLIFOQueue
java.util.Collections$CheckedCollection
java.util.Collections$CheckedCollection$1
java.util.Collections$CheckedList
java.util.Collections$CheckedList$1
java.util.Collections$CheckedMap
java.util.Collections$CheckedMap$CheckedEntrySet
java.util.Collections$CheckedMap$CheckedEntrySet$1
java.util.Collections$CheckedMap$CheckedEntrySet$CheckedEntry
java.util.Collections$CheckedRandomAccessList
java.util.Collections$CheckedSet
java.util.Collections$CheckedSortedMap
java.util.Collections$CheckedSortedSet
java.util.Collections$CopiesList
java.util.Collections$EmptyEnumeration
java.util.Collections$EmptyIterator
java.util.Collections$EmptyList:
    private static final long serialVersionUID
    3669:3669:public java.util.Iterator iterator()
    3672:3672:public java.util.ListIterator listIterator()
    3675:3675:public int size()
    3676:3676:public boolean isEmpty()
    3678:3678:public boolean contains(java.lang.Object)
    3679:3679:public boolean containsAll(java.util.Collection)
    3681:3681:public java.lang.Object[] toArray()
    3684:3686:public java.lang.Object[] toArray(java.lang.Object[])
    3690:3690:public java.lang.Object get(int)
    3694:3694:public boolean equals(java.lang.Object)
    3697:3697:public int hashCode()
    3701:3702:public boolean removeIf(java.util.function.Predicate)
    3708:3709:public void forEach(java.util.function.Consumer)
    3712:3712:public java.util.Spliterator spliterator()
    3716:3717:public void replaceAll(java.util.function.UnaryOperator)
    3720:3720:public void sort(java.util.Comparator)
    3725:3725:private java.lang.Object readResolve()
java.util.Collections$EmptyListIterator
java.util.Collections$EmptyMap:
    private static final long serialVersionUID
    3770:3770:public int size()
    3771:3771:public boolean isEmpty()
    3772:3772:public boolean containsKey(java.lang.Object)
    3773:3773:public boolean containsValue(java.lang.Object)
    3774:3774:public java.lang.Object get(java.lang.Object)
    3775:3775:public java.util.Set keySet()
    3776:3776:public java.util.Collection values()
    3777:3777:public java.util.Set entrySet()
    3780:3780:public boolean equals(java.lang.Object)
    3783:3783:public int hashCode()
    3789:3789:public java.lang.Object getOrDefault(java.lang.Object,java.lang.Object)
    3794:3795:public void forEach(java.util.function.BiConsumer)
    3799:3800:public void replaceAll(java.util.function.BiFunction)
    3804:3804:public java.lang.Object putIfAbsent(java.lang.Object,java.lang.Object)
    3809:3809:public boolean remove(java.lang.Object,java.lang.Object)
    3814:3814:public boolean replace(java.lang.Object,java.lang.Object,java.lang.Object)
    3819:3819:public java.lang.Object replace(java.lang.Object,java.lang.Object)
    3825:3825:public java.lang.Object computeIfAbsent(java.lang.Object,java.util.function.Function)
    3831:3831:public java.lang.Object computeIfPresent(java.lang.Object,java.util.function.BiFunction)
    3837:3837:public java.lang.Object compute(java.lang.Object,java.util.function.BiFunction)
    3843:3843:public java.lang.Object merge(java.lang.Object,java.lang.Object,java.util.function.BiFunction)
    3848:3848:private java.lang.Object readResolve()
java.util.Collections$EmptySet:
    private static final long serialVersionUID
    3593:3593:public java.util.Iterator iterator()
    3595:3595:public int size()
    3596:3596:public boolean isEmpty()
    3598:3598:public boolean contains(java.lang.Object)
    3599:3599:public boolean containsAll(java.util.Collection)
    3601:3601:public java.lang.Object[] toArray()
    3604:3606:public java.lang.Object[] toArray(java.lang.Object[])
    3612:3613:public void forEach(java.util.function.Consumer)
    3616:3617:public boolean removeIf(java.util.function.Predicate)
    3620:3620:public java.util.Spliterator spliterator()
    3624:3624:private java.lang.Object readResolve()
java.util.Collections$ReverseComparator
java.util.Collections$ReverseComparator2
java.util.Collections$SetFromMap
java.util.Collections$SingletonList
java.util.Collections$SingletonMap
java.util.Collections$SingletonSet:
    private static final long serialVersionUID
    3953:3953:public java.util.Iterator iterator()
    3956:3956:public int size()
    3958:3958:public boolean contains(java.lang.Object)
    3963:3964:public void forEach(java.util.function.Consumer)
    3967:3967:public java.util.Spliterator spliterator()
    3971:3971:public boolean removeIf(java.util.function.Predicate)
java.util.Collections$SynchronizedCollection
java.util.Collections$SynchronizedList
java.util.Collections$SynchronizedMap
java.util.Collections$SynchronizedRandomAccessList
java.util.Collections$SynchronizedSet
java.util.Collections$SynchronizedSortedMap
java.util.Collections$SynchronizedSortedSet
java.util.Collections$UnmodifiableCollection
java.util.Collections$UnmodifiableCollection$1
java.util.Collections$UnmodifiableList
java.util.Collections$UnmodifiableList$1
java.util.Collections$UnmodifiableMap
java.util.Collections$UnmodifiableMap$UnmodifiableEntrySet
java.util.Collections$UnmodifiableMap$UnmodifiableEntrySet$1
java.util.Collections$UnmodifiableMap$UnmodifiableEntrySet$UnmodifiableEntry
java.util.Collections$UnmodifiableMap$UnmodifiableEntrySet$UnmodifiableEntrySetSpliterator
java.util.Collections$UnmodifiableRandomAccessList
java.util.Collections$UnmodifiableSet
java.util.Collections$UnmodifiableSortedMap
java.util.Collections$UnmodifiableSortedSet
java.util.ComparableTimSort
java.util.Comparator
java.util.Comparators
java.util.Comparators$NaturalOrderComparator
java.util.Comparators$NullComparator
java.util.ConcurrentModificationException
java.util.Currency
java.util.Date
java.util.Date$GcalHolder
java.util.Deque
java.util.Dictionary
java.util.DoubleSummaryStatistics
java.util.DualPivotQuicksort
java.util.DuplicateFormatFlagsException
java.util.EmptyStackException
java.util.EnumMap
java.util.EnumMap$1
java.util.EnumMap$EntryIterator
java.util.EnumMap$EntrySet
java.util.EnumMap$EnumMapEntry
java.util.EnumMap$EnumMapIterator
java.util.EnumMap$KeyIterator
java.util.EnumMap$KeySet
java.util.EnumMap$ValueIterator
java.util.EnumMap$Values
java.util.EnumSet
java.util.EnumSet$SerializationProxy
java.util.Enumeration
java.util.EventListener
java.util.EventListenerProxy
java.util.EventObject
java.util.FormatFlagsConversionMismatchException
java.util.Formattable
java.util.FormattableFlags
java.util.Formatter
java.util.Formatter$BigDecimalLayoutForm
java.util.Formatter$Conversion
java.util.Formatter$DateTime
java.util.Formatter$FixedString
java.util.Formatter$Flags
java.util.Formatter$FormatSpecifier
java.util.Formatter$FormatSpecifier$BigDecimalLayout
java.util.Formatter$FormatSpecifierParser
java.util.Formatter$FormatString
java.util.FormatterClosedException
java.util.Grego
java.util.GregorianCalendar
java.util.HashMap
java.util.HashMap$1
java.util.HashMap$EntryIterator
java.util.HashMap$EntrySet
java.util.HashMap$EntrySpliterator
java.util.HashMap$HashIterator
java.util.HashMap$HashMapEntry
java.util.HashMap$HashMapSpliterator
java.util.HashMap$KeyIterator
java.util.HashMap$KeySet
java.util.HashMap$KeySpliterator
java.util.HashMap$ValueIterator
java.util.HashMap$ValueSpliterator
java.util.HashMap$Values
java.util.HashSet
java.util.Hashtable
java.util.Hashtable$1
java.util.Hashtable$EntrySet
java.util.Hashtable$Enumerator
java.util.Hashtable$HashtableEntry
java.util.Hashtable$KeySet
java.util.Hashtable$ValueCollection
java.util.IdentityHashMap
java.util.IdentityHashMap$1
java.util.IdentityHashMap$EntryIterator
java.util.IdentityHashMap$EntrySet
java.util.IdentityHashMap$EntrySpliterator
java.util.IdentityHashMap$IdentityEntry
java.util.IdentityHashMap$IdentityHashMapIterator
java.util.IdentityHashMap$IdentityHashMapSpliterator
java.util.IdentityHashMap$KeyIterator
java.util.IdentityHashMap$KeySet
java.util.IdentityHashMap$KeySpliterator
java.util.IdentityHashMap$ValueIterator
java.util.IdentityHashMap$ValueSpliterator
java.util.IdentityHashMap$Values
java.util.IllegalFormatCodePointException
java.util.IllegalFormatConversionException
java.util.IllegalFormatException
java.util.IllegalFormatFlagsException
java.util.IllegalFormatPrecisionException
java.util.IllegalFormatWidthException
java.util.IllformedLocaleException
java.util.InputMismatchException
java.util.IntSummaryStatistics
java.util.InvalidPropertiesFormatException
java.util.Iterator
java.util.JumboEnumSet
java.util.JumboEnumSet$EnumSetIterator
java.util.LinkedHashMap
java.util.LinkedHashMap$1
java.util.LinkedHashMap$EntryIterator
java.util.LinkedHashMap$KeyIterator
java.util.LinkedHashMap$LinkedHashIterator
java.util.LinkedHashMap$LinkedHashMapEntry
java.util.LinkedHashMap$ValueIterator
java.util.LinkedHashSet
java.util.LinkedList
java.util.LinkedList$1
java.util.LinkedList$DescendingIterator
java.util.LinkedList$LLSpliterator
java.util.LinkedList$ListItr
java.util.LinkedList$Node
java.util.List:
    public abstract int size()
    public abstract boolean isEmpty()
    public abstract boolean contains(java.lang.Object)
    public abstract java.util.Iterator iterator()
    public abstract java.lang.Object[] toArray()
    public abstract java.lang.Object[] toArray(java.lang.Object[])
    public abstract boolean add(java.lang.Object)
    public abstract boolean remove(java.lang.Object)
    public abstract boolean containsAll(java.util.Collection)
    public abstract boolean addAll(java.util.Collection)
    public abstract boolean addAll(int,java.util.Collection)
    public abstract boolean removeAll(java.util.Collection)
    public abstract boolean retainAll(java.util.Collection)
    public abstract void clear()
    public abstract boolean equals(java.lang.Object)
    public abstract int hashCode()
    public abstract java.lang.Object get(int)
    public abstract java.lang.Object set(int,java.lang.Object)
    public abstract void add(int,java.lang.Object)
    public abstract java.lang.Object remove(int)
    public abstract int indexOf(java.lang.Object)
    public abstract int lastIndexOf(java.lang.Object)
    public abstract java.util.ListIterator listIterator()
    public abstract java.util.ListIterator listIterator(int)
    public abstract java.util.List subList(int,int)
    625:625:public java.util.Spliterator spliterator()
    658:663:public void replaceAll(java.util.function.UnaryOperator)
    686:687:public void sort(java.util.Comparator)
java.util.ListIterator
java.util.ListResourceBundle
java.util.Locale
java.util.Locale$1
java.util.Locale$Builder
java.util.Locale$Cache
java.util.Locale$Category
java.util.Locale$LocaleKey
java.util.LongSummaryStatistics
java.util.Map:
    public abstract int size()
    public abstract boolean isEmpty()
    public abstract boolean containsKey(java.lang.Object)
    public abstract boolean containsValue(java.lang.Object)
    public abstract java.lang.Object get(java.lang.Object)
    public abstract java.lang.Object put(java.lang.Object,java.lang.Object)
    public abstract java.lang.Object remove(java.lang.Object)
    public abstract void putAll(java.util.Map)
    public abstract void clear()
    public abstract java.util.Set keySet()
    public abstract java.util.Collection values()
    public abstract java.util.Set entrySet()
    public abstract boolean equals(java.lang.Object)
    public abstract int hashCode()
    590:592:public java.lang.Object getOrDefault(java.lang.Object,java.lang.Object)
    621:634:public void forEach(java.util.function.BiConsumer)
    676:698:public void replaceAll(java.util.function.BiFunction)
    744:749:public java.lang.Object putIfAbsent(java.lang.Object,java.lang.Object)
    787:793:public boolean remove(java.lang.Object,java.lang.Object)
    839:845:public boolean replace(java.lang.Object,java.lang.Object,java.lang.Object)
    888:891:public java.lang.Object replace(java.lang.Object,java.lang.Object)
    970:980:public java.lang.Object computeIfAbsent(java.lang.Object,java.util.function.Function)
    1047:1059:public java.lang.Object computeIfPresent(java.lang.Object,java.util.function.BiFunction)
    1139:1156:public java.lang.Object compute(java.lang.Object,java.util.function.BiFunction)
    1237:1247:public java.lang.Object merge(java.lang.Object,java.lang.Object,java.util.function.BiFunction)
java.util.Map$Entry
java.util.MissingFormatArgumentException
java.util.MissingFormatWidthException
java.util.MissingResourceException
java.util.NavigableMap
java.util.NavigableSet
java.util.NoSuchElementException
java.util.Objects
java.util.Observable
java.util.Observer
java.util.Optional
java.util.OptionalDouble
java.util.OptionalInt
java.util.OptionalLong
java.util.PrimitiveIterator
java.util.PrimitiveIterator$OfDouble
java.util.PrimitiveIterator$OfInt
java.util.PrimitiveIterator$OfLong
java.util.PriorityQueue
java.util.PriorityQueue$1
java.util.PriorityQueue$Itr
java.util.PriorityQueue$PriorityQueueSpliterator
java.util.Properties
java.util.Properties$LineReader
java.util.Properties$XmlLoader
java.util.PropertyPermission
java.util.PropertyResourceBundle
java.util.Queue
java.util.Random
java.util.Random$RandomDoublesSpliterator
java.util.Random$RandomIntsSpliterator
java.util.Random$RandomLongsSpliterator
java.util.RandomAccess
java.util.RandomAccessSubList
java.util.RegularEnumSet
java.util.RegularEnumSet$EnumSetIterator
java.util.ResourceBundle
java.util.ResourceBundle$Control
java.util.ResourceBundle$MissingBundle
java.util.ResourceBundle$NoFallbackControl
java.util.ResourceBundle$SimpleControl
java.util.Scanner
java.util.Scanner$1
java.util.ServiceConfigurationError
java.util.ServiceLoader
java.util.ServiceLoader$1
java.util.ServiceLoader$1ProviderIterator
java.util.ServiceLoader$LazyIterator
java.util.Set:
    public abstract int size()
    public abstract boolean isEmpty()
    public abstract boolean contains(java.lang.Object)
    public abstract java.util.Iterator iterator()
    public abstract java.lang.Object[] toArray()
    public abstract java.lang.Object[] toArray(java.lang.Object[])
    public abstract boolean add(java.lang.Object)
    public abstract boolean remove(java.lang.Object)
    public abstract boolean containsAll(java.util.Collection)
    public abstract boolean addAll(java.util.Collection)
    public abstract boolean retainAll(java.util.Collection)
    public abstract boolean removeAll(java.util.Collection)
    public abstract void clear()
    public abstract boolean equals(java.lang.Object)
    public abstract int hashCode()
    411:411:public java.util.Spliterator spliterator()
java.util.SimpleTimeZone
java.util.SimpleTimeZone$GcalHolder
java.util.SortedMap
java.util.SortedSet
java.util.SortedSet$1
java.util.Spliterator
java.util.Spliterator$OfDouble
java.util.Spliterator$OfInt
java.util.Spliterator$OfLong
java.util.Spliterator$OfPrimitive
java.util.Spliterators
java.util.Spliterators$1Adapter
java.util.Spliterators$2Adapter
java.util.Spliterators$3Adapter
java.util.Spliterators$4Adapter
java.util.Spliterators$AbstractDoubleSpliterator
java.util.Spliterators$AbstractDoubleSpliterator$HoldingDoubleConsumer
java.util.Spliterators$AbstractIntSpliterator
java.util.Spliterators$AbstractIntSpliterator$HoldingIntConsumer
java.util.Spliterators$AbstractLongSpliterator
java.util.Spliterators$AbstractLongSpliterator$HoldingLongConsumer
java.util.Spliterators$AbstractSpliterator
java.util.Spliterators$AbstractSpliterator$HoldingConsumer
java.util.Spliterators$ArraySpliterator
java.util.Spliterators$DoubleArraySpliterator
java.util.Spliterators$DoubleIteratorSpliterator
java.util.Spliterators$EmptySpliterator
java.util.Spliterators$EmptySpliterator$OfDouble
java.util.Spliterators$EmptySpliterator$OfInt
java.util.Spliterators$EmptySpliterator$OfLong
java.util.Spliterators$EmptySpliterator$OfRef
java.util.Spliterators$IntArraySpliterator
java.util.Spliterators$IntIteratorSpliterator
java.util.Spliterators$IteratorSpliterator
java.util.Spliterators$LongArraySpliterator
java.util.Spliterators$LongIteratorSpliterator
java.util.Stack
java.util.StringJoiner
java.util.StringTokenizer
java.util.SubList
java.util.SubList$1
java.util.TaskQueue
java.util.TimSort
java.util.TimeZone
java.util.TimeZone$AvailableIDsGetter
java.util.TimeZone$GMTHolder
java.util.TimeZone$NoImagePreloadHolder
java.util.TimeZone$UTCHolder
java.util.Timer
java.util.Timer$1
java.util.TimerTask
java.util.TimerThread
java.util.TooManyListenersException
java.util.TreeMap
java.util.TreeMap$AscendingSubMap
java.util.TreeMap$AscendingSubMap$AscendingEntrySetView
java.util.TreeMap$DescendingKeyIterator
java.util.TreeMap$DescendingKeySpliterator
java.util.TreeMap$DescendingSubMap
java.util.TreeMap$DescendingSubMap$DescendingEntrySetView
java.util.TreeMap$EntryIterator
java.util.TreeMap$EntrySet
java.util.TreeMap$EntrySpliterator
java.util.TreeMap$KeyIterator
java.util.TreeMap$KeySet
java.util.TreeMap$KeySpliterator
java.util.TreeMap$NavigableSubMap
java.util.TreeMap$NavigableSubMap$DescendingSubMapEntryIterator
java.util.TreeMap$NavigableSubMap$DescendingSubMapKeyIterator
java.util.TreeMap$NavigableSubMap$EntrySetView
java.util.TreeMap$NavigableSubMap$SubMapEntryIterator
java.util.TreeMap$NavigableSubMap$SubMapIterator
java.util.TreeMap$NavigableSubMap$SubMapKeyIterator
java.util.TreeMap$PrivateEntryIterator
java.util.TreeMap$SubMap
java.util.TreeMap$TreeMapEntry
java.util.TreeMap$TreeMapSpliterator
java.util.TreeMap$ValueIterator
java.util.TreeMap$ValueSpliterator
java.util.TreeMap$Values
java.util.TreeSet
java.util.UUID
java.util.UUID$Holder
java.util.UnknownFormatConversionException
java.util.UnknownFormatFlagsException
java.util.UnsafeArrayList
java.util.Vector
java.util.Vector$1
java.util.Vector$Itr
java.util.Vector$ListItr
java.util.Vector$VectorSpliterator
java.util.WeakHashMap
java.util.WeakHashMap$1
java.util.WeakHashMap$Entry
java.util.WeakHashMap$EntryIterator
java.util.WeakHashMap$EntrySet
java.util.WeakHashMap$EntrySpliterator
java.util.WeakHashMap$HashIterator
java.util.WeakHashMap$KeyIterator
java.util.WeakHashMap$KeySet
java.util.WeakHashMap$KeySpliterator
java.util.WeakHashMap$ValueIterator
java.util.WeakHashMap$ValueSpliterator
java.util.WeakHashMap$Values
java.util.WeakHashMap$WeakHashMapSpliterator
java.util.concurrent.AbstractExecutorService
java.util.concurrent.ArrayBlockingQueue
java.util.concurrent.ArrayBlockingQueue$Itr
java.util.concurrent.ArrayBlockingQueue$Itrs
java.util.concurrent.ArrayBlockingQueue$Itrs$Node
java.util.concurrent.BlockingDeque
java.util.concurrent.BlockingQueue
java.util.concurrent.BrokenBarrierException
java.util.concurrent.Callable
java.util.concurrent.CancellationException
java.util.concurrent.CompletionService
java.util.concurrent.ConcurrentHashMap
java.util.concurrent.ConcurrentHashMap$BaseIterator
java.util.concurrent.ConcurrentHashMap$BulkTask
java.util.concurrent.ConcurrentHashMap$CollectionView
java.util.concurrent.ConcurrentHashMap$CounterCell
java.util.concurrent.ConcurrentHashMap$EntryIterator
java.util.concurrent.ConcurrentHashMap$EntrySetView
java.util.concurrent.ConcurrentHashMap$EntrySpliterator
java.util.concurrent.ConcurrentHashMap$ForEachEntryTask
java.util.concurrent.ConcurrentHashMap$ForEachKeyTask
java.util.concurrent.ConcurrentHashMap$ForEachMappingTask
java.util.concurrent.ConcurrentHashMap$ForEachTransformedEntryTask
java.util.concurrent.ConcurrentHashMap$ForEachTransformedKeyTask
java.util.concurrent.ConcurrentHashMap$ForEachTransformedMappingTask
java.util.concurrent.ConcurrentHashMap$ForEachTransformedValueTask
java.util.concurrent.ConcurrentHashMap$ForEachValueTask
java.util.concurrent.ConcurrentHashMap$ForwardingNode
java.util.concurrent.ConcurrentHashMap$KeyIterator
java.util.concurrent.ConcurrentHashMap$KeySetView
java.util.concurrent.ConcurrentHashMap$KeySpliterator
java.util.concurrent.ConcurrentHashMap$MapEntry
java.util.concurrent.ConcurrentHashMap$MapReduceEntriesTask
java.util.concurrent.ConcurrentHashMap$MapReduceEntriesToDoubleTask
java.util.concurrent.ConcurrentHashMap$MapReduceEntriesToIntTask
java.util.concurrent.ConcurrentHashMap$MapReduceEntriesToLongTask
java.util.concurrent.ConcurrentHashMap$MapReduceKeysTask
java.util.concurrent.ConcurrentHashMap$MapReduceKeysToDoubleTask
java.util.concurrent.ConcurrentHashMap$MapReduceKeysToIntTask
java.util.concurrent.ConcurrentHashMap$MapReduceKeysToLongTask
java.util.concurrent.ConcurrentHashMap$MapReduceMappingsTask
java.util.concurrent.ConcurrentHashMap$MapReduceMappingsToDoubleTask
java.util.concurrent.ConcurrentHashMap$MapReduceMappingsToIntTask
java.util.concurrent.ConcurrentHashMap$MapReduceMappingsToLongTask
java.util.concurrent.ConcurrentHashMap$MapReduceValuesTask
java.util.concurrent.ConcurrentHashMap$MapReduceValuesToDoubleTask
java.util.concurrent.ConcurrentHashMap$MapReduceValuesToIntTask
java.util.concurrent.ConcurrentHashMap$MapReduceValuesToLongTask
java.util.concurrent.ConcurrentHashMap$Node
java.util.concurrent.ConcurrentHashMap$ReduceEntriesTask
java.util.concurrent.ConcurrentHashMap$ReduceKeysTask
java.util.concurrent.ConcurrentHashMap$ReduceValuesTask
java.util.concurrent.ConcurrentHashMap$ReservationNode
java.util.concurrent.ConcurrentHashMap$SearchEntriesTask
java.util.concurrent.ConcurrentHashMap$SearchKeysTask
java.util.concurrent.ConcurrentHashMap$SearchMappingsTask
java.util.concurrent.ConcurrentHashMap$SearchValuesTask
java.util.concurrent.ConcurrentHashMap$Segment
java.util.concurrent.ConcurrentHashMap$TableStack
java.util.concurrent.ConcurrentHashMap$Traverser
java.util.concurrent.ConcurrentHashMap$TreeBin
java.util.concurrent.ConcurrentHashMap$TreeNode
java.util.concurrent.ConcurrentHashMap$ValueIterator
java.util.concurrent.ConcurrentHashMap$ValueSpliterator
java.util.concurrent.ConcurrentHashMap$ValuesView
java.util.concurrent.ConcurrentLinkedDeque
java.util.concurrent.ConcurrentLinkedDeque$1
java.util.concurrent.ConcurrentLinkedDeque$AbstractItr
java.util.concurrent.ConcurrentLinkedDeque$CLDSpliterator
java.util.concurrent.ConcurrentLinkedDeque$DescendingItr
java.util.concurrent.ConcurrentLinkedDeque$Itr
java.util.concurrent.ConcurrentLinkedDeque$Node
java.util.concurrent.ConcurrentLinkedQueue
java.util.concurrent.ConcurrentLinkedQueue$1
java.util.concurrent.ConcurrentLinkedQueue$CLQSpliterator
java.util.concurrent.ConcurrentLinkedQueue$Itr
java.util.concurrent.ConcurrentLinkedQueue$Node
java.util.concurrent.ConcurrentMap
java.util.concurrent.ConcurrentNavigableMap
java.util.concurrent.ConcurrentSkipListMap
java.util.concurrent.ConcurrentSkipListMap$CSLMSpliterator
java.util.concurrent.ConcurrentSkipListMap$EntryIterator
java.util.concurrent.ConcurrentSkipListMap$EntrySet
java.util.concurrent.ConcurrentSkipListMap$EntrySpliterator
java.util.concurrent.ConcurrentSkipListMap$HeadIndex
java.util.concurrent.ConcurrentSkipListMap$Index
java.util.concurrent.ConcurrentSkipListMap$Iter
java.util.concurrent.ConcurrentSkipListMap$KeyIterator
java.util.concurrent.ConcurrentSkipListMap$KeySet
java.util.concurrent.ConcurrentSkipListMap$KeySpliterator
java.util.concurrent.ConcurrentSkipListMap$Node
java.util.concurrent.ConcurrentSkipListMap$SubMap
java.util.concurrent.ConcurrentSkipListMap$SubMap$SubMapEntryIterator
java.util.concurrent.ConcurrentSkipListMap$SubMap$SubMapIter
java.util.concurrent.ConcurrentSkipListMap$SubMap$SubMapKeyIterator
java.util.concurrent.ConcurrentSkipListMap$SubMap$SubMapValueIterator
java.util.concurrent.ConcurrentSkipListMap$ValueIterator
java.util.concurrent.ConcurrentSkipListMap$ValueSpliterator
java.util.concurrent.ConcurrentSkipListMap$Values
java.util.concurrent.ConcurrentSkipListSet
java.util.concurrent.CopyOnWriteArrayList
java.util.concurrent.CopyOnWriteArrayList$CowIterator
java.util.concurrent.CopyOnWriteArrayList$CowSubList
java.util.concurrent.CopyOnWriteArrayList$Slice
java.util.concurrent.CopyOnWriteArraySet
java.util.concurrent.CountDownLatch
java.util.concurrent.CountDownLatch$Sync
java.util.concurrent.CountedCompleter
java.util.concurrent.CyclicBarrier
java.util.concurrent.CyclicBarrier$1
java.util.concurrent.CyclicBarrier$Generation
java.util.concurrent.DelayQueue
java.util.concurrent.DelayQueue$Itr
java.util.concurrent.Delayed
java.util.concurrent.Exchanger
java.util.concurrent.Exchanger$Node
java.util.concurrent.Exchanger$Participant
java.util.concurrent.ExecutionException
java.util.concurrent.Executor
java.util.concurrent.ExecutorCompletionService
java.util.concurrent.ExecutorCompletionService$QueueingFuture
java.util.concurrent.ExecutorService
java.util.concurrent.Executors
java.util.concurrent.Executors$1
java.util.concurrent.Executors$2
java.util.concurrent.Executors$DefaultThreadFactory
java.util.concurrent.Executors$DelegatedExecutorService
java.util.concurrent.Executors$DelegatedScheduledExecutorService
java.util.concurrent.Executors$FinalizableDelegatedExecutorService
java.util.concurrent.Executors$PrivilegedCallableUsingCurrentClassLoader
java.util.concurrent.Executors$PrivilegedThreadFactory
java.util.concurrent.Executors$PrivilegedThreadFactory$1
java.util.concurrent.Executors$RunnableAdapter
java.util.concurrent.ForkJoinPool
java.util.concurrent.ForkJoinPool$1
java.util.concurrent.ForkJoinPool$AuxState
java.util.concurrent.ForkJoinPool$DefaultForkJoinWorkerThreadFactory
java.util.concurrent.ForkJoinPool$EmptyTask
java.util.concurrent.ForkJoinPool$ForkJoinWorkerThreadFactory
java.util.concurrent.ForkJoinPool$ManagedBlocker
java.util.concurrent.ForkJoinPool$WorkQueue
java.util.concurrent.ForkJoinTask
java.util.concurrent.ForkJoinTask$AdaptedCallable
java.util.concurrent.ForkJoinTask$AdaptedRunnable
java.util.concurrent.ForkJoinTask$AdaptedRunnableAction
java.util.concurrent.ForkJoinTask$ExceptionNode
java.util.concurrent.ForkJoinTask$RunnableExecuteAction
java.util.concurrent.ForkJoinWorkerThread
java.util.concurrent.Future
java.util.concurrent.FutureTask
java.util.concurrent.FutureTask$WaitNode
java.util.concurrent.Helpers
java.util.concurrent.LinkedBlockingDeque
java.util.concurrent.LinkedBlockingDeque$1
java.util.concurrent.LinkedBlockingDeque$AbstractItr
java.util.concurrent.LinkedBlockingDeque$DescendingItr
java.util.concurrent.LinkedBlockingDeque$Itr
java.util.concurrent.LinkedBlockingDeque$LBDSpliterator
java.util.concurrent.LinkedBlockingDeque$Node
java.util.concurrent.LinkedBlockingQueue
java.util.concurrent.LinkedBlockingQueue$Itr
java.util.concurrent.LinkedBlockingQueue$LBQSpliterator
java.util.concurrent.LinkedBlockingQueue$Node
java.util.concurrent.LinkedTransferQueue
java.util.concurrent.LinkedTransferQueue$Itr
java.util.concurrent.LinkedTransferQueue$LTQSpliterator
java.util.concurrent.LinkedTransferQueue$Node
java.util.concurrent.Phaser
java.util.concurrent.Phaser$QNode
java.util.concurrent.PriorityBlockingQueue
java.util.concurrent.PriorityBlockingQueue$Itr
java.util.concurrent.PriorityBlockingQueue$PBQSpliterator
java.util.concurrent.RecursiveAction
java.util.concurrent.RecursiveTask
java.util.concurrent.RejectedExecutionException
java.util.concurrent.RejectedExecutionHandler
java.util.concurrent.RunnableFuture
java.util.concurrent.RunnableScheduledFuture
java.util.concurrent.ScheduledExecutorService
java.util.concurrent.ScheduledFuture
java.util.concurrent.ScheduledThreadPoolExecutor
java.util.concurrent.ScheduledThreadPoolExecutor$DelayedWorkQueue
java.util.concurrent.ScheduledThreadPoolExecutor$DelayedWorkQueue$Itr
java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask
java.util.concurrent.Semaphore
java.util.concurrent.Semaphore$FairSync
java.util.concurrent.Semaphore$NonfairSync
java.util.concurrent.Semaphore$Sync
java.util.concurrent.SynchronousQueue
java.util.concurrent.SynchronousQueue$FifoWaitQueue
java.util.concurrent.SynchronousQueue$LifoWaitQueue
java.util.concurrent.SynchronousQueue$TransferQueue
java.util.concurrent.SynchronousQueue$TransferQueue$QNode
java.util.concurrent.SynchronousQueue$TransferStack
java.util.concurrent.SynchronousQueue$TransferStack$SNode
java.util.concurrent.SynchronousQueue$Transferer
java.util.concurrent.SynchronousQueue$WaitQueue
java.util.concurrent.ThreadFactory
java.util.concurrent.ThreadLocalRandom
java.util.concurrent.ThreadLocalRandom$RandomDoublesSpliterator
java.util.concurrent.ThreadLocalRandom$RandomIntsSpliterator
java.util.concurrent.ThreadLocalRandom$RandomLongsSpliterator
java.util.concurrent.ThreadPoolExecutor
java.util.concurrent.ThreadPoolExecutor$AbortPolicy
java.util.concurrent.ThreadPoolExecutor$CallerRunsPolicy
java.util.concurrent.ThreadPoolExecutor$DiscardOldestPolicy
java.util.concurrent.ThreadPoolExecutor$DiscardPolicy
java.util.concurrent.ThreadPoolExecutor$Worker
java.util.concurrent.TimeUnit
java.util.concurrent.TimeUnit$1
java.util.concurrent.TimeUnit$2
java.util.concurrent.TimeUnit$3
java.util.concurrent.TimeUnit$4
java.util.concurrent.TimeUnit$5
java.util.concurrent.TimeUnit$6
java.util.concurrent.TimeUnit$7
java.util.concurrent.TimeoutException
java.util.concurrent.TransferQueue
java.util.concurrent.atomic.AtomicBoolean
java.util.concurrent.atomic.AtomicInteger
java.util.concurrent.atomic.AtomicIntegerArray
java.util.concurrent.atomic.AtomicIntegerFieldUpdater
java.util.concurrent.atomic.AtomicIntegerFieldUpdater$AtomicIntegerFieldUpdaterImpl
java.util.concurrent.atomic.AtomicLong
java.util.concurrent.atomic.AtomicLongArray
java.util.concurrent.atomic.AtomicLongFieldUpdater
java.util.concurrent.atomic.AtomicLongFieldUpdater$CASUpdater
java.util.concurrent.atomic.AtomicLongFieldUpdater$LockedUpdater
java.util.concurrent.atomic.AtomicMarkableReference
java.util.concurrent.atomic.AtomicMarkableReference$Pair
java.util.concurrent.atomic.AtomicReference
java.util.concurrent.atomic.AtomicReferenceArray
java.util.concurrent.atomic.AtomicReferenceFieldUpdater
java.util.concurrent.atomic.AtomicReferenceFieldUpdater$AtomicReferenceFieldUpdaterImpl
java.util.concurrent.atomic.AtomicStampedReference
java.util.concurrent.atomic.AtomicStampedReference$Pair
java.util.concurrent.locks.AbstractOwnableSynchronizer
java.util.concurrent.locks.AbstractQueuedLongSynchronizer
java.util.concurrent.locks.AbstractQueuedLongSynchronizer$ConditionObject
java.util.concurrent.locks.AbstractQueuedSynchronizer
java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject
java.util.concurrent.locks.AbstractQueuedSynchronizer$Node
java.util.concurrent.locks.Condition
java.util.concurrent.locks.Lock
java.util.concurrent.locks.LockSupport
java.util.concurrent.locks.ReadWriteLock
java.util.concurrent.locks.ReentrantLock
java.util.concurrent.locks.ReentrantLock$FairSync
java.util.concurrent.locks.ReentrantLock$NonfairSync
java.util.concurrent.locks.ReentrantLock$Sync
java.util.concurrent.locks.ReentrantReadWriteLock
java.util.concurrent.locks.ReentrantReadWriteLock$FairSync
java.util.concurrent.locks.ReentrantReadWriteLock$NonfairSync
java.util.concurrent.locks.ReentrantReadWriteLock$ReadLock
java.util.concurrent.locks.ReentrantReadWriteLock$Sync
java.util.concurrent.locks.ReentrantReadWriteLock$Sync$HoldCounter
java.util.concurrent.locks.ReentrantReadWriteLock$Sync$ThreadLocalHoldCounter
java.util.concurrent.locks.ReentrantReadWriteLock$WriteLock
java.util.function.BiConsumer
java.util.function.BiFunction
java.util.function.BiPredicate
java.util.function.BinaryOperator
java.util.function.BooleanSupplier
java.util.function.Consumer
java.util.function.DoubleBinaryOperator
java.util.function.DoubleConsumer
java.util.function.DoubleFunction
java.util.function.DoublePredicate
java.util.function.DoubleSupplier
java.util.function.DoubleToIntFunction
java.util.function.DoubleToLongFunction
java.util.function.DoubleUnaryOperator
java.util.function.Function
java.util.function.IntBinaryOperator
java.util.function.IntConsumer
java.util.function.IntFunction
java.util.function.IntPredicate
java.util.function.IntSupplier
java.util.function.IntToDoubleFunction
java.util.function.IntToLongFunction
java.util.function.IntUnaryOperator
java.util.function.LongBinaryOperator
java.util.function.LongConsumer
java.util.function.LongFunction
java.util.function.LongPredicate
java.util.function.LongSupplier
java.util.function.LongToDoubleFunction
java.util.function.LongToIntFunction
java.util.function.LongUnaryOperator
java.util.function.ObjDoubleConsumer
java.util.function.ObjIntConsumer
java.util.function.ObjLongConsumer
java.util.function.Predicate
java.util.function.Supplier
java.util.function.ToDoubleBiFunction
java.util.function.ToDoubleFunction
java.util.function.ToIntBiFunction
java.util.function.ToIntFunction
java.util.function.ToLongBiFunction
java.util.function.ToLongFunction
java.util.function.UnaryOperator
java.util.jar.Attributes
java.util.jar.Attributes$Name
java.util.jar.JarEntry
java.util.jar.JarException
java.util.jar.JarFile
java.util.jar.JarFile$1
java.util.jar.JarFile$2
java.util.jar.JarFile$JarFileEntry
java.util.jar.JarInputStream
java.util.jar.JarOutputStream
java.util.jar.JarVerifier
java.util.jar.JarVerifier$1
java.util.jar.JarVerifier$2
java.util.jar.JarVerifier$3
java.util.jar.JarVerifier$4
java.util.jar.JarVerifier$VerifierCodeSource
java.util.jar.JarVerifier$VerifierStream
java.util.jar.Manifest
java.util.jar.Manifest$FastInputStream
java.util.logging.ConsoleHandler
java.util.logging.ErrorManager
java.util.logging.FileHandler
java.util.logging.FileHandler$1
java.util.logging.FileHandler$InitializationErrorManager
java.util.logging.FileHandler$MeteredStream
java.util.logging.Filter
java.util.logging.Formatter
java.util.logging.Handler
java.util.logging.Level
java.util.logging.Level$KnownLevel
java.util.logging.LogManager
java.util.logging.LogManager$1
java.util.logging.LogManager$Cleaner
java.util.logging.LogManager$LogNode
java.util.logging.LogManager$LoggerContext
java.util.logging.LogManager$LoggerWeakRef
java.util.logging.LogManager$RootLogger
java.util.logging.LogManager$SystemLoggerContext
java.util.logging.LogRecord
java.util.logging.Logger
java.util.logging.Logger$LoggerHelper
java.util.logging.Logging
java.util.logging.LoggingMXBean
java.util.logging.LoggingPermission
java.util.logging.LoggingProxyImpl
java.util.logging.MemoryHandler
java.util.logging.SimpleFormatter
java.util.logging.StreamHandler
java.util.logging.XMLFormatter
java.util.regex.MatchResult
java.util.regex.Matcher
java.util.regex.Matcher$OffsetBasedMatchResult
java.util.regex.Pattern
java.util.regex.Pattern$1MatcherIterator
java.util.regex.PatternSyntaxException
java.util.stream.AbstractPipeline
java.util.stream.AbstractShortCircuitTask
java.util.stream.AbstractSpinedBuffer
java.util.stream.AbstractTask
java.util.stream.BaseStream
java.util.stream.Collector
java.util.stream.Collector$Characteristics
java.util.stream.Collectors
java.util.stream.Collectors$1OptionalBox
java.util.stream.Collectors$CollectorImpl
java.util.stream.Collectors$Partition
java.util.stream.Collectors$Partition$1
java.util.stream.DistinctOps
java.util.stream.DistinctOps$1
java.util.stream.DistinctOps$1$1
java.util.stream.DistinctOps$1$2
java.util.stream.DoublePipeline
java.util.stream.DoublePipeline$1
java.util.stream.DoublePipeline$1$1
java.util.stream.DoublePipeline$2
java.util.stream.DoublePipeline$2$1
java.util.stream.DoublePipeline$3
java.util.stream.DoublePipeline$3$1
java.util.stream.DoublePipeline$4
java.util.stream.DoublePipeline$4$1
java.util.stream.DoublePipeline$5
java.util.stream.DoublePipeline$5$1
java.util.stream.DoublePipeline$6
java.util.stream.DoublePipeline$7
java.util.stream.DoublePipeline$7$1
java.util.stream.DoublePipeline$8
java.util.stream.DoublePipeline$8$1
java.util.stream.DoublePipeline$Head
java.util.stream.DoublePipeline$StatefulOp
java.util.stream.DoublePipeline$StatelessOp
java.util.stream.DoubleStream
java.util.stream.DoubleStream$1
java.util.stream.DoubleStream$Builder
java.util.stream.FindOps
java.util.stream.FindOps$FindOp
java.util.stream.FindOps$FindSink
java.util.stream.FindOps$FindSink$OfDouble
java.util.stream.FindOps$FindSink$OfInt
java.util.stream.FindOps$FindSink$OfLong
java.util.stream.FindOps$FindSink$OfRef
java.util.stream.FindOps$FindTask
java.util.stream.ForEachOps
java.util.stream.ForEachOps$ForEachOp
java.util.stream.ForEachOps$ForEachOp$OfDouble
java.util.stream.ForEachOps$ForEachOp$OfInt
java.util.stream.ForEachOps$ForEachOp$OfLong
java.util.stream.ForEachOps$ForEachOp$OfRef
java.util.stream.ForEachOps$ForEachOrderedTask
java.util.stream.ForEachOps$ForEachTask
java.util.stream.IntPipeline
java.util.stream.IntPipeline$1
java.util.stream.IntPipeline$1$1
java.util.stream.IntPipeline$10
java.util.stream.IntPipeline$10$1
java.util.stream.IntPipeline$2
java.util.stream.IntPipeline$2$1
java.util.stream.IntPipeline$3
java.util.stream.IntPipeline$3$1
java.util.stream.IntPipeline$4
java.util.stream.IntPipeline$4$1
java.util.stream.IntPipeline$5
java.util.stream.IntPipeline$5$1
java.util.stream.IntPipeline$6
java.util.stream.IntPipeline$6$1
java.util.stream.IntPipeline$7
java.util.stream.IntPipeline$7$1
java.util.stream.IntPipeline$8
java.util.stream.IntPipeline$9
java.util.stream.IntPipeline$9$1
java.util.stream.IntPipeline$Head
java.util.stream.IntPipeline$StatefulOp
java.util.stream.IntPipeline$StatelessOp
java.util.stream.IntStream
java.util.stream.IntStream$1
java.util.stream.IntStream$Builder
java.util.stream.LongPipeline
java.util.stream.LongPipeline$1
java.util.stream.LongPipeline$1$1
java.util.stream.LongPipeline$2
java.util.stream.LongPipeline$2$1
java.util.stream.LongPipeline$3
java.util.stream.LongPipeline$3$1
java.util.stream.LongPipeline$4
java.util.stream.LongPipeline$4$1
java.util.stream.LongPipeline$5
java.util.stream.LongPipeline$5$1
java.util.stream.LongPipeline$6
java.util.stream.LongPipeline$6$1
java.util.stream.LongPipeline$7
java.util.stream.LongPipeline$8
java.util.stream.LongPipeline$8$1
java.util.stream.LongPipeline$9
java.util.stream.LongPipeline$9$1
java.util.stream.LongPipeline$Head
java.util.stream.LongPipeline$StatefulOp
java.util.stream.LongPipeline$StatelessOp
java.util.stream.LongStream
java.util.stream.LongStream$1
java.util.stream.LongStream$Builder
java.util.stream.MatchOps
java.util.stream.MatchOps$1MatchSink
java.util.stream.MatchOps$2MatchSink
java.util.stream.MatchOps$3MatchSink
java.util.stream.MatchOps$4MatchSink
java.util.stream.MatchOps$BooleanTerminalSink
java.util.stream.MatchOps$MatchKind
java.util.stream.MatchOps$MatchOp
java.util.stream.MatchOps$MatchTask
java.util.stream.Node
java.util.stream.Node$Builder
java.util.stream.Node$Builder$OfDouble
java.util.stream.Node$Builder$OfInt
java.util.stream.Node$Builder$OfLong
java.util.stream.Node$OfDouble
java.util.stream.Node$OfInt
java.util.stream.Node$OfLong
java.util.stream.Node$OfPrimitive
java.util.stream.Nodes
java.util.stream.Nodes$1
java.util.stream.Nodes$AbstractConcNode
java.util.stream.Nodes$ArrayNode
java.util.stream.Nodes$CollectionNode
java.util.stream.Nodes$CollectorTask
java.util.stream.Nodes$CollectorTask$OfDouble
java.util.stream.Nodes$CollectorTask$OfInt
java.util.stream.Nodes$CollectorTask$OfLong
java.util.stream.Nodes$CollectorTask$OfRef
java.util.stream.Nodes$ConcNode
java.util.stream.Nodes$ConcNode$OfDouble
java.util.stream.Nodes$ConcNode$OfInt
java.util.stream.Nodes$ConcNode$OfLong
java.util.stream.Nodes$ConcNode$OfPrimitive
java.util.stream.Nodes$DoubleArrayNode
java.util.stream.Nodes$DoubleFixedNodeBuilder
java.util.stream.Nodes$DoubleSpinedNodeBuilder
java.util.stream.Nodes$EmptyNode
java.util.stream.Nodes$EmptyNode$OfDouble
java.util.stream.Nodes$EmptyNode$OfInt
java.util.stream.Nodes$EmptyNode$OfLong
java.util.stream.Nodes$EmptyNode$OfRef
java.util.stream.Nodes$FixedNodeBuilder
java.util.stream.Nodes$IntArrayNode
java.util.stream.Nodes$IntFixedNodeBuilder
java.util.stream.Nodes$IntSpinedNodeBuilder
java.util.stream.Nodes$InternalNodeSpliterator
java.util.stream.Nodes$InternalNodeSpliterator$OfDouble
java.util.stream.Nodes$InternalNodeSpliterator$OfInt
java.util.stream.Nodes$InternalNodeSpliterator$OfLong
java.util.stream.Nodes$InternalNodeSpliterator$OfPrimitive
java.util.stream.Nodes$InternalNodeSpliterator$OfRef
java.util.stream.Nodes$LongArrayNode
java.util.stream.Nodes$LongFixedNodeBuilder
java.util.stream.Nodes$LongSpinedNodeBuilder
java.util.stream.Nodes$SizedCollectorTask
java.util.stream.Nodes$SizedCollectorTask$OfDouble
java.util.stream.Nodes$SizedCollectorTask$OfInt
java.util.stream.Nodes$SizedCollectorTask$OfLong
java.util.stream.Nodes$SizedCollectorTask$OfRef
java.util.stream.Nodes$SpinedNodeBuilder
java.util.stream.Nodes$ToArrayTask
java.util.stream.Nodes$ToArrayTask$OfDouble
java.util.stream.Nodes$ToArrayTask$OfInt
java.util.stream.Nodes$ToArrayTask$OfLong
java.util.stream.Nodes$ToArrayTask$OfPrimitive
java.util.stream.Nodes$ToArrayTask$OfRef
java.util.stream.PipelineHelper
java.util.stream.ReduceOps
java.util.stream.ReduceOps$1
java.util.stream.ReduceOps$10
java.util.stream.ReduceOps$10ReducingSink
java.util.stream.ReduceOps$11
java.util.stream.ReduceOps$11ReducingSink
java.util.stream.ReduceOps$12
java.util.stream.ReduceOps$12ReducingSink
java.util.stream.ReduceOps$13
java.util.stream.ReduceOps$13ReducingSink
java.util.stream.ReduceOps$1ReducingSink
java.util.stream.ReduceOps$2
java.util.stream.ReduceOps$2ReducingSink
java.util.stream.ReduceOps$3
java.util.stream.ReduceOps$3ReducingSink
java.util.stream.ReduceOps$4
java.util.stream.ReduceOps$4ReducingSink
java.util.stream.ReduceOps$5
java.util.stream.ReduceOps$5ReducingSink
java.util.stream.ReduceOps$6
java.util.stream.ReduceOps$6ReducingSink
java.util.stream.ReduceOps$7
java.util.stream.ReduceOps$7ReducingSink
java.util.stream.ReduceOps$8
java.util.stream.ReduceOps$8ReducingSink
java.util.stream.ReduceOps$9
java.util.stream.ReduceOps$9ReducingSink
java.util.stream.ReduceOps$AccumulatingSink
java.util.stream.ReduceOps$Box
java.util.stream.ReduceOps$ReduceOp
java.util.stream.ReduceOps$ReduceTask
java.util.stream.ReferencePipeline
java.util.stream.ReferencePipeline$1
java.util.stream.ReferencePipeline$10
java.util.stream.ReferencePipeline$10$1
java.util.stream.ReferencePipeline$11
java.util.stream.ReferencePipeline$11$1
java.util.stream.ReferencePipeline$2
java.util.stream.ReferencePipeline$2$1
java.util.stream.ReferencePipeline$3
java.util.stream.ReferencePipeline$3$1
java.util.stream.ReferencePipeline$4
java.util.stream.ReferencePipeline$4$1
java.util.stream.ReferencePipeline$5
java.util.stream.ReferencePipeline$5$1
java.util.stream.ReferencePipeline$6
java.util.stream.ReferencePipeline$6$1
java.util.stream.ReferencePipeline$7
java.util.stream.ReferencePipeline$7$1
java.util.stream.ReferencePipeline$8
java.util.stream.ReferencePipeline$8$1
java.util.stream.ReferencePipeline$9
java.util.stream.ReferencePipeline$9$1
java.util.stream.ReferencePipeline$Head
java.util.stream.ReferencePipeline$StatefulOp
java.util.stream.ReferencePipeline$StatelessOp
java.util.stream.Sink
java.util.stream.Sink$ChainedDouble
java.util.stream.Sink$ChainedInt
java.util.stream.Sink$ChainedLong
java.util.stream.Sink$ChainedReference
java.util.stream.Sink$OfDouble
java.util.stream.Sink$OfInt
java.util.stream.Sink$OfLong
java.util.stream.SliceOps
java.util.stream.SliceOps$1
java.util.stream.SliceOps$1$1
java.util.stream.SliceOps$2
java.util.stream.SliceOps$2$1
java.util.stream.SliceOps$3
java.util.stream.SliceOps$3$1
java.util.stream.SliceOps$4
java.util.stream.SliceOps$4$1
java.util.stream.SliceOps$5
java.util.stream.SliceOps$SliceTask
java.util.stream.SortedOps
java.util.stream.SortedOps$AbstractDoubleSortingSink
java.util.stream.SortedOps$AbstractIntSortingSink
java.util.stream.SortedOps$AbstractLongSortingSink
java.util.stream.SortedOps$AbstractRefSortingSink
java.util.stream.SortedOps$DoubleSortingSink
java.util.stream.SortedOps$IntSortingSink
java.util.stream.SortedOps$LongSortingSink
java.util.stream.SortedOps$OfDouble
java.util.stream.SortedOps$OfInt
java.util.stream.SortedOps$OfLong
java.util.stream.SortedOps$OfRef
java.util.stream.SortedOps$RefSortingSink
java.util.stream.SortedOps$SizedDoubleSortingSink
java.util.stream.SortedOps$SizedIntSortingSink
java.util.stream.SortedOps$SizedLongSortingSink
java.util.stream.SortedOps$SizedRefSortingSink
java.util.stream.SpinedBuffer
java.util.stream.SpinedBuffer$1Splitr
java.util.stream.SpinedBuffer$OfDouble
java.util.stream.SpinedBuffer$OfDouble$1Splitr
java.util.stream.SpinedBuffer$OfInt
java.util.stream.SpinedBuffer$OfInt$1Splitr
java.util.stream.SpinedBuffer$OfLong
java.util.stream.SpinedBuffer$OfLong$1Splitr
java.util.stream.SpinedBuffer$OfPrimitive
java.util.stream.SpinedBuffer$OfPrimitive$BaseSpliterator
java.util.stream.Stream
java.util.stream.Stream$1
java.util.stream.Stream$Builder
java.util.stream.StreamOpFlag
java.util.stream.StreamOpFlag$MaskBuilder
java.util.stream.StreamOpFlag$Type
java.util.stream.StreamShape
java.util.stream.StreamSpliterators
java.util.stream.StreamSpliterators$1
java.util.stream.StreamSpliterators$AbstractWrappingSpliterator
java.util.stream.StreamSpliterators$ArrayBuffer
java.util.stream.StreamSpliterators$ArrayBuffer$OfDouble
java.util.stream.StreamSpliterators$ArrayBuffer$OfInt
java.util.stream.StreamSpliterators$ArrayBuffer$OfLong
java.util.stream.StreamSpliterators$ArrayBuffer$OfPrimitive
java.util.stream.StreamSpliterators$ArrayBuffer$OfRef
java.util.stream.StreamSpliterators$DelegatingSpliterator
java.util.stream.StreamSpliterators$DelegatingSpliterator$OfDouble
java.util.stream.StreamSpliterators$DelegatingSpliterator$OfInt
java.util.stream.StreamSpliterators$DelegatingSpliterator$OfLong
java.util.stream.StreamSpliterators$DelegatingSpliterator$OfPrimitive
java.util.stream.StreamSpliterators$DistinctSpliterator
java.util.stream.StreamSpliterators$DoubleWrappingSpliterator
java.util.stream.StreamSpliterators$InfiniteSupplyingSpliterator
java.util.stream.StreamSpliterators$InfiniteSupplyingSpliterator$OfDouble
java.util.stream.StreamSpliterators$InfiniteSupplyingSpliterator$OfInt
java.util.stream.StreamSpliterators$InfiniteSupplyingSpliterator$OfLong
java.util.stream.StreamSpliterators$InfiniteSupplyingSpliterator$OfRef
java.util.stream.StreamSpliterators$IntWrappingSpliterator
java.util.stream.StreamSpliterators$LongWrappingSpliterator
java.util.stream.StreamSpliterators$SliceSpliterator
java.util.stream.StreamSpliterators$SliceSpliterator$OfDouble
java.util.stream.StreamSpliterators$SliceSpliterator$OfInt
java.util.stream.StreamSpliterators$SliceSpliterator$OfLong
java.util.stream.StreamSpliterators$SliceSpliterator$OfPrimitive
java.util.stream.StreamSpliterators$SliceSpliterator$OfRef
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$OfDouble
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$OfInt
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$OfLong
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$OfPrimitive
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$OfRef
java.util.stream.StreamSpliterators$UnorderedSliceSpliterator$PermitStatus
java.util.stream.StreamSpliterators$WrappingSpliterator
java.util.stream.StreamSupport
java.util.stream.Streams
java.util.stream.Streams$1
java.util.stream.Streams$2
java.util.stream.Streams$AbstractStreamBuilderImpl
java.util.stream.Streams$ConcatSpliterator
java.util.stream.Streams$ConcatSpliterator$OfDouble
java.util.stream.Streams$ConcatSpliterator$OfInt
java.util.stream.Streams$ConcatSpliterator$OfLong
java.util.stream.Streams$ConcatSpliterator$OfPrimitive
java.util.stream.Streams$ConcatSpliterator$OfRef
java.util.stream.Streams$DoubleStreamBuilderImpl
java.util.stream.Streams$IntStreamBuilderImpl
java.util.stream.Streams$LongStreamBuilderImpl
java.util.stream.Streams$RangeIntSpliterator
java.util.stream.Streams$RangeLongSpliterator
java.util.stream.Streams$StreamBuilderImpl
java.util.stream.TerminalOp
java.util.stream.TerminalSink
java.util.zip.Adler32
java.util.zip.CRC32
java.util.zip.CheckedInputStream
java.util.zip.CheckedOutputStream
java.util.zip.Checksum
java.util.zip.DataFormatException
java.util.zip.Deflater
java.util.zip.DeflaterInputStream
java.util.zip.DeflaterOutputStream
java.util.zip.GZIPInputStream
java.util.zip.GZIPOutputStream
java.util.zip.Inflater
java.util.zip.InflaterInputStream
java.util.zip.InflaterOutputStream
java.util.zip.ZStreamRef
java.util.zip.ZipCoder
java.util.zip.ZipConstants
java.util.zip.ZipConstants64
java.util.zip.ZipEntry
java.util.zip.ZipError
java.util.zip.ZipException
java.util.zip.ZipFile
java.util.zip.ZipFile$1
java.util.zip.ZipFile$ZipFileInflaterInputStream
java.util.zip.ZipFile$ZipFileInputStream
java.util.zip.ZipInputStream
java.util.zip.ZipOutputStream
java.util.zip.ZipOutputStream$XEntry
javax.annotation.Generated
javax.annotation.PostConstruct
javax.annotation.PreDestroy
javax.annotation.Resource
javax.annotation.Resource$AuthenticationType
javax.annotation.Resources
javax.crypto.BadPaddingException
javax.crypto.Cipher
javax.crypto.Cipher$1
javax.crypto.Cipher$CipherSpiAndProvider
javax.crypto.Cipher$InitParams
javax.crypto.Cipher$InitType
javax.crypto.Cipher$NeedToSet
javax.crypto.Cipher$SpiAndProviderUpdater
javax.crypto.Cipher$Transform
javax.crypto.CipherInputStream
javax.crypto.CipherOutputStream
javax.crypto.CipherSpi
javax.crypto.ExemptionMechanism
javax.crypto.ExemptionMechanismException
javax.crypto.ExemptionMechanismSpi
javax.crypto.IllegalBlockSizeException
javax.crypto.JceSecurity
javax.crypto.KeyAgreement
javax.crypto.KeyAgreementSpi
javax.crypto.KeyGenerator
javax.crypto.KeyGeneratorSpi
javax.crypto.Mac
javax.crypto.MacSpi
javax.crypto.NoSuchPaddingException
javax.crypto.NullCipher
javax.crypto.NullCipherSpi
javax.crypto.SealedObject
javax.crypto.SecretKey
javax.crypto.SecretKeyFactory
javax.crypto.SecretKeyFactorySpi
javax.crypto.ShortBufferException
javax.crypto.extObjectInputStream
javax.crypto.interfaces.DHKey
javax.crypto.interfaces.DHPrivateKey
javax.crypto.interfaces.DHPublicKey
javax.crypto.interfaces.PBEKey
javax.crypto.spec.DESKeySpec
javax.crypto.spec.DESedeKeySpec
javax.crypto.spec.DHGenParameterSpec
javax.crypto.spec.DHParameterSpec
javax.crypto.spec.DHPrivateKeySpec
javax.crypto.spec.DHPublicKeySpec
javax.crypto.spec.GCMParameterSpec
javax.crypto.spec.IvParameterSpec
javax.crypto.spec.OAEPParameterSpec
javax.crypto.spec.PBEKeySpec
javax.crypto.spec.PBEParameterSpec
javax.crypto.spec.PSource
javax.crypto.spec.PSource$PSpecified
javax.crypto.spec.RC2ParameterSpec
javax.crypto.spec.RC5ParameterSpec
javax.crypto.spec.SecretKeySpec
javax.lang.model.element.Modifier
javax.lang.model.type.TypeKind
javax.net.DefaultServerSocketFactory
javax.net.DefaultSocketFactory
javax.net.ServerSocketFactory
javax.net.SocketFactory
javax.net.ssl.DefaultSSLServerSocketFactory
javax.net.ssl.DefaultSSLSocketFactory
javax.net.ssl.HandshakeCompletedEvent
javax.net.ssl.HandshakeCompletedListener
javax.net.ssl.HostnameVerifier
javax.net.ssl.HttpsURLConnection
javax.net.ssl.HttpsURLConnection$NoPreloadHolder
javax.net.ssl.KeyManager
javax.net.ssl.KeyManagerFactory
javax.net.ssl.KeyManagerFactory$1
javax.net.ssl.KeyManagerFactorySpi
javax.net.ssl.ManagerFactoryParameters
javax.net.ssl.SNIHostName
javax.net.ssl.SNIHostName$SNIHostNameMatcher
javax.net.ssl.SNIMatcher
javax.net.ssl.SNIServerName
javax.net.ssl.SSLContext
javax.net.ssl.SSLContextSpi
javax.net.ssl.SSLEngine
javax.net.ssl.SSLEngineResult
javax.net.ssl.SSLEngineResult$HandshakeStatus
javax.net.ssl.SSLEngineResult$Status
javax.net.ssl.SSLException
javax.net.ssl.SSLHandshakeException
javax.net.ssl.SSLKeyException
javax.net.ssl.SSLParameters
javax.net.ssl.SSLPeerUnverifiedException
javax.net.ssl.SSLProtocolException
javax.net.ssl.SSLServerSocket
javax.net.ssl.SSLServerSocketFactory
javax.net.ssl.SSLSession
javax.net.ssl.SSLSessionBindingEvent
javax.net.ssl.SSLSessionBindingListener
javax.net.ssl.SSLSessionContext
javax.net.ssl.SSLSocket
javax.net.ssl.SSLSocketFactory
javax.net.ssl.SSLSocketFactory$1
javax.net.ssl.StandardConstants
javax.net.ssl.TrustManager
javax.net.ssl.TrustManagerFactory
javax.net.ssl.TrustManagerFactory$1
javax.net.ssl.TrustManagerFactorySpi
javax.net.ssl.X509TrustManager
javax.security.auth.DestroyFailedException
javax.security.auth.Destroyable
javax.security.auth.callback.Callback
javax.security.auth.callback.CallbackHandler
javax.security.auth.callback.PasswordCallback
javax.security.auth.callback.UnsupportedCallbackException
javax.security.auth.x500.X500Principal
javax.security.cert.Certificate
javax.security.cert.CertificateEncodingException
javax.security.cert.CertificateException
javax.security.cert.CertificateExpiredException
javax.security.cert.CertificateNotYetValidException
javax.security.cert.CertificateParsingException
javax.security.cert.X509Certificate
javax.security.cert.X509Certificate$1
javax.xml.XMLConstants
javax.xml.datatype.DatatypeConfigurationException
javax.xml.datatype.DatatypeConstants
javax.xml.datatype.DatatypeConstants$1
javax.xml.datatype.DatatypeConstants$Field
javax.xml.datatype.DatatypeFactory
javax.xml.datatype.Duration
javax.xml.datatype.FactoryFinder
javax.xml.datatype.FactoryFinder$CacheHolder
javax.xml.datatype.FactoryFinder$ConfigurationError
javax.xml.datatype.XMLGregorianCalendar
javax.xml.namespace.NamespaceContext
javax.xml.namespace.QName
javax.xml.parsers.DocumentBuilder
javax.xml.parsers.DocumentBuilderFactory
javax.xml.parsers.FactoryConfigurationError
javax.xml.parsers.FilePathToURI
javax.xml.parsers.ParserConfigurationException
javax.xml.parsers.SAXParser
javax.xml.parsers.SAXParserFactory
javax.xml.transform.ErrorListener
javax.xml.transform.OutputKeys
javax.xml.transform.Result
javax.xml.transform.Source
javax.xml.transform.SourceLocator
javax.xml.transform.Templates
javax.xml.transform.Transformer
javax.xml.transform.TransformerConfigurationException
javax.xml.transform.TransformerException
javax.xml.transform.TransformerFactory
javax.xml.transform.TransformerFactoryConfigurationError
javax.xml.transform.URIResolver
javax.xml.transform.dom.DOMLocator
javax.xml.transform.dom.DOMResult
javax.xml.transform.dom.DOMSource
javax.xml.transform.sax.SAXResult
javax.xml.transform.sax.SAXSource
javax.xml.transform.sax.SAXTransformerFactory
javax.xml.transform.sax.TemplatesHandler
javax.xml.transform.sax.TransformerHandler
javax.xml.transform.stream.FilePathToURI
javax.xml.transform.stream.StreamResult
javax.xml.transform.stream.StreamSource
javax.xml.validation.Schema
javax.xml.validation.SchemaFactory
javax.xml.validation.SchemaFactoryFinder
javax.xml.validation.SchemaFactoryFinder$CacheHolder
javax.xml.validation.SchemaFactoryLoader
javax.xml.validation.TypeInfoProvider
javax.xml.validation.Validator
javax.xml.validation.ValidatorHandler
javax.xml.xpath.XPath
javax.xml.xpath.XPathConstants
javax.xml.xpath.XPathException
javax.xml.xpath.XPathExpression
javax.xml.xpath.XPathExpressionException
javax.xml.xpath.XPathFactory
javax.xml.xpath.XPathFactoryConfigurationException
javax.xml.xpath.XPathFactoryFinder
javax.xml.xpath.XPathFactoryFinder$CacheHolder
javax.xml.xpath.XPathFunction
javax.xml.xpath.XPathFunctionException
javax.xml.xpath.XPathFunctionResolver
javax.xml.xpath.XPathVariableResolver
libcore.icu.ICU
libcore.icu.LocaleData
libcore.icu.NativeIDN
libcore.icu.TimeZoneNames
libcore.icu.TimeZoneNames$1
libcore.icu.TimeZoneNames$ZoneStringsCache
libcore.internal.StringPool
libcore.io.AsynchronousCloseMonitor
libcore.io.Base64
libcore.io.BufferIterator
libcore.io.DeleteOnExit
libcore.io.IoBridge
libcore.io.IoUtils
libcore.io.Libcore
libcore.io.Memory
libcore.io.NetworkBridge
libcore.io.NetworkOs
libcore.io.Os
libcore.io.OsConstants
libcore.io.Posix
libcore.io.SizeOf
libcore.io.Streams
libcore.io.StructFlock
libcore.io.StructGroupReq
libcore.io.StructGroupSourceReq
libcore.io.StructLinger
libcore.io.StructPollfd
libcore.io.StructStat
libcore.io.StructStatVfs
libcore.io.StructTimeval
libcore.io.StructUtsname
libcore.net.MimeUtils
libcore.net.UriCodec
libcore.net.http.HttpDate
libcore.net.http.HttpDate$1
libcore.net.url.JarHandler
libcore.net.url.JarURLConnectionImpl
libcore.net.url.JarURLConnectionImpl$JarURLConnectionInputStream
libcore.net.url.UrlUtils
libcore.reflect.AnnotatedElements
libcore.reflect.GenericArrayTypeImpl
libcore.reflect.GenericSignatureParser
libcore.reflect.ListOfTypes
libcore.reflect.ListOfVariables
libcore.reflect.ParameterizedTypeImpl
libcore.reflect.TypeVariableImpl
libcore.reflect.Types
libcore.reflect.WildcardTypeImpl
libcore.util.BasicLruCache
libcore.util.CountingOutputStream
libcore.util.EmptyArray
libcore.util.MutableInt
libcore.util.MutableLong
libcore.util.Objects
libcore.util.SneakyThrow
org.apache.harmony.beans.BeansUtils
org.apache.harmony.xml.dom.AttrImpl
org.apache.harmony.xml.dom.CDATASectionImpl
org.apache.harmony.xml.dom.CharacterDataImpl
org.apache.harmony.xml.dom.CommentImpl
org.apache.harmony.xml.dom.DOMConfigurationImpl
org.apache.harmony.xml.dom.DOMConfigurationImpl$1
org.apache.harmony.xml.dom.DOMConfigurationImpl$10
org.apache.harmony.xml.dom.DOMConfigurationImpl$11
org.apache.harmony.xml.dom.DOMConfigurationImpl$12
org.apache.harmony.xml.dom.DOMConfigurationImpl$13
org.apache.harmony.xml.dom.DOMConfigurationImpl$2
org.apache.harmony.xml.dom.DOMConfigurationImpl$3
org.apache.harmony.xml.dom.DOMConfigurationImpl$4
org.apache.harmony.xml.dom.DOMConfigurationImpl$5
org.apache.harmony.xml.dom.DOMConfigurationImpl$6
org.apache.harmony.xml.dom.DOMConfigurationImpl$7
org.apache.harmony.xml.dom.DOMConfigurationImpl$8
org.apache.harmony.xml.dom.DOMConfigurationImpl$9
org.apache.harmony.xml.dom.DOMConfigurationImpl$BooleanParameter
org.apache.harmony.xml.dom.DOMConfigurationImpl$FixedParameter
org.apache.harmony.xml.dom.DOMConfigurationImpl$Parameter
org.apache.harmony.xml.dom.DOMErrorImpl
org.apache.harmony.xml.dom.DOMErrorImpl$1
org.apache.harmony.xml.dom.DOMImplementationImpl
org.apache.harmony.xml.dom.DocumentFragmentImpl
org.apache.harmony.xml.dom.DocumentImpl
org.apache.harmony.xml.dom.DocumentTypeImpl
org.apache.harmony.xml.dom.ElementImpl
org.apache.harmony.xml.dom.ElementImpl$ElementAttrNamedNodeMapImpl
org.apache.harmony.xml.dom.EntityImpl
org.apache.harmony.xml.dom.EntityReferenceImpl
org.apache.harmony.xml.dom.InnerNodeImpl
org.apache.harmony.xml.dom.LeafNodeImpl
org.apache.harmony.xml.dom.NodeImpl
org.apache.harmony.xml.dom.NodeImpl$1
org.apache.harmony.xml.dom.NodeImpl$UserData
org.apache.harmony.xml.dom.NodeListImpl
org.apache.harmony.xml.dom.NotationImpl
org.apache.harmony.xml.dom.ProcessingInstructionImpl
org.apache.harmony.xml.dom.TextImpl
org.apache.harmony.xml.parsers.DocumentBuilderFactoryImpl
org.apache.harmony.xml.parsers.DocumentBuilderImpl
org.apache.harmony.xml.parsers.SAXParserFactoryImpl
org.apache.harmony.xml.parsers.SAXParserImpl
org.json.JSON
org.json.JSONArray
org.json.JSONException
org.json.JSONObject
org.json.JSONObject$1
org.json.JSONStringer
org.json.JSONStringer$Scope
org.json.JSONTokener
org.kxml2.io.KXmlParser
org.kxml2.io.KXmlParser$ContentSource
org.kxml2.io.KXmlParser$ValueContext
org.kxml2.io.KXmlSerializer
org.w3c.dom.Attr
org.w3c.dom.CDATASection
org.w3c.dom.CharacterData
org.w3c.dom.Comment
org.w3c.dom.DOMConfiguration
org.w3c.dom.DOMError
org.w3c.dom.DOMErrorHandler
org.w3c.dom.DOMException
org.w3c.dom.DOMImplementation
org.w3c.dom.DOMImplementationList
org.w3c.dom.DOMImplementationSource
org.w3c.dom.DOMLocator
org.w3c.dom.DOMStringList
org.w3c.dom.Document
org.w3c.dom.DocumentFragment
org.w3c.dom.DocumentType
org.w3c.dom.Element
org.w3c.dom.Entity
org.w3c.dom.EntityReference
org.w3c.dom.NameList
org.w3c.dom.NamedNodeMap
org.w3c.dom.Node
org.w3c.dom.NodeList
org.w3c.dom.Notation
org.w3c.dom.ProcessingInstruction
org.w3c.dom.Text
org.w3c.dom.TypeInfo
org.w3c.dom.UserDataHandler
org.w3c.dom.ls.DOMImplementationLS
org.w3c.dom.ls.LSException
org.w3c.dom.ls.LSInput
org.w3c.dom.ls.LSOutput
org.w3c.dom.ls.LSParser
org.w3c.dom.ls.LSParserFilter
org.w3c.dom.ls.LSResourceResolver
org.w3c.dom.ls.LSSerializer
org.w3c.dom.ls.LSSerializerFilter
org.w3c.dom.traversal.NodeFilter
org.w3c.dom.traversal.NodeIterator
org.xml.sax.AttributeList
org.xml.sax.Attributes
org.xml.sax.ContentHandler
org.xml.sax.DTDHandler
org.xml.sax.DocumentHandler
org.xml.sax.EntityResolver
org.xml.sax.ErrorHandler
org.xml.sax.HandlerBase
org.xml.sax.InputSource
org.xml.sax.Locator
org.xml.sax.Parser
org.xml.sax.SAXException
org.xml.sax.SAXNotRecognizedException
org.xml.sax.SAXNotSupportedException
org.xml.sax.SAXParseException
org.xml.sax.XMLFilter
org.xml.sax.XMLReader
org.xml.sax.ext.Attributes2
org.xml.sax.ext.Attributes2Impl
org.xml.sax.ext.DeclHandler
org.xml.sax.ext.DefaultHandler2
org.xml.sax.ext.EntityResolver2
org.xml.sax.ext.LexicalHandler
org.xml.sax.ext.Locator2
org.xml.sax.ext.Locator2Impl
org.xml.sax.helpers.AttributeListImpl
org.xml.sax.helpers.AttributesImpl
org.xml.sax.helpers.DefaultHandler
org.xml.sax.helpers.LocatorImpl
org.xml.sax.helpers.NamespaceSupport
org.xml.sax.helpers.NamespaceSupport$Context
org.xml.sax.helpers.NewInstance
org.xml.sax.helpers.ParserAdapter
org.xml.sax.helpers.ParserAdapter$AttributeListAdapter
org.xml.sax.helpers.ParserFactory
org.xml.sax.helpers.XMLFilterImpl
org.xml.sax.helpers.XMLReaderAdapter
org.xml.sax.helpers.XMLReaderAdapter$AttributesAdapter
org.xml.sax.helpers.XMLReaderFactory
org.xmlpull.v1.XmlPullParser
org.xmlpull.v1.XmlPullParserException
org.xmlpull.v1.XmlPullParserFactory
org.xmlpull.v1.XmlSerializer
org.xmlpull.v1.sax2.Driver
sun.misc.ASCIICaseInsensitiveComparator
sun.misc.BASE64Decoder
sun.misc.CEFormatException
sun.misc.CEStreamExhausted
sun.misc.CharacterDecoder
sun.misc.CharacterEncoder
sun.misc.Cleaner
sun.misc.CompoundEnumeration
sun.misc.DoubleConsts
sun.misc.FDBigInt
sun.misc.FDBigInteger
sun.misc.FloatConsts
sun.misc.FloatingDecimal
sun.misc.FloatingDecimal$1
sun.misc.FloatingDecimal$ASCIIToBinaryBuffer
sun.misc.FloatingDecimal$ASCIIToBinaryConverter
sun.misc.FloatingDecimal$BinaryToASCIIBuffer
sun.misc.FloatingDecimal$BinaryToASCIIConverter
sun.misc.FloatingDecimal$ExceptionalBinaryToASCIIBuffer
sun.misc.FloatingDecimal$HexFloatPattern
sun.misc.FloatingDecimal$PreparedASCIIToBinaryBuffer
sun.misc.FormattedFloatingDecimal
sun.misc.FormattedFloatingDecimal$1
sun.misc.FormattedFloatingDecimal$2
sun.misc.FormattedFloatingDecimal$Form
sun.misc.FpUtils
sun.misc.Hashing
sun.misc.HexDumpEncoder
sun.misc.IOUtils
sun.misc.IoTrace
sun.misc.LRUCache
sun.misc.Unsafe
sun.net.ApplicationProxy
sun.net.ConnectionResetException
sun.net.DefaultProgressMeteringPolicy
sun.net.NetHooks
sun.net.ProgressEvent
sun.net.ProgressListener
sun.net.ProgressMeteringPolicy
sun.net.ProgressMonitor
sun.net.ProgressSource
sun.net.ProgressSource$State
sun.net.ResourceManager
sun.net.SocksProxy
sun.net.spi.nameservice.NameService
sun.net.util.IPAddressUtil
sun.net.www.MessageHeader
sun.net.www.MessageHeader$HeaderIterator
sun.net.www.MeteredStream
sun.net.www.ParseUtil
sun.net.www.URLConnection
sun.net.www.protocol.file.FileURLConnection
sun.net.www.protocol.file.Handler
sun.nio.ch.AbstractPollArrayWrapper
sun.nio.ch.AbstractPollSelectorImpl
sun.nio.ch.AllocatedNativeObject
sun.nio.ch.ChannelInputStream
sun.nio.ch.DatagramChannelImpl
sun.nio.ch.DatagramChannelImpl$DefaultOptionsHolder
sun.nio.ch.DatagramDispatcher
sun.nio.ch.DatagramSocketAdaptor
sun.nio.ch.DatagramSocketAdaptor$1
sun.nio.ch.DefaultSelectorProvider
sun.nio.ch.DirectBuffer
sun.nio.ch.ExtendedSocketOption
sun.nio.ch.ExtendedSocketOption$1
sun.nio.ch.FileChannelImpl
sun.nio.ch.FileChannelImpl$1
sun.nio.ch.FileChannelImpl$SimpleFileLockTable
sun.nio.ch.FileChannelImpl$Unmapper
sun.nio.ch.FileDescriptorHolderSocketImpl
sun.nio.ch.FileDispatcher
sun.nio.ch.FileDispatcherImpl
sun.nio.ch.FileKey
sun.nio.ch.FileLockImpl
sun.nio.ch.FileLockTable
sun.nio.ch.IOStatus
sun.nio.ch.IOUtil
sun.nio.ch.IOVecWrapper
sun.nio.ch.IOVecWrapper$Deallocator
sun.nio.ch.InheritedChannel
sun.nio.ch.InheritedChannel$InheritedDatagramChannelImpl
sun.nio.ch.InheritedChannel$InheritedServerSocketChannelImpl
sun.nio.ch.InheritedChannel$InheritedSocketChannelImpl
sun.nio.ch.Interruptible
sun.nio.ch.NativeDispatcher
sun.nio.ch.NativeObject
sun.nio.ch.NativeThread
sun.nio.ch.NativeThreadSet
sun.nio.ch.Net
sun.nio.ch.Net$1
sun.nio.ch.Net$2
sun.nio.ch.Net$3
sun.nio.ch.Net$4
sun.nio.ch.OptionKey
sun.nio.ch.PipeImpl
sun.nio.ch.PollArrayWrapper
sun.nio.ch.PollSelectorImpl
sun.nio.ch.PollSelectorProvider
sun.nio.ch.Reflect
sun.nio.ch.Reflect$1
sun.nio.ch.Reflect$ReflectionError
sun.nio.ch.SelChImpl
sun.nio.ch.SelectionKeyImpl
sun.nio.ch.SelectorImpl
sun.nio.ch.SelectorProviderImpl
sun.nio.ch.ServerSocketAdaptor
sun.nio.ch.ServerSocketChannelImpl
sun.nio.ch.ServerSocketChannelImpl$DefaultOptionsHolder
sun.nio.ch.SharedFileLockTable
sun.nio.ch.SharedFileLockTable$FileLockReference
sun.nio.ch.SinkChannelImpl
sun.nio.ch.SocketAdaptor
sun.nio.ch.SocketAdaptor$1
sun.nio.ch.SocketAdaptor$2
sun.nio.ch.SocketAdaptor$SocketInputStream
sun.nio.ch.SocketChannelImpl
sun.nio.ch.SocketChannelImpl$DefaultOptionsHolder
sun.nio.ch.SocketDispatcher
sun.nio.ch.SocketOptionRegistry
sun.nio.ch.SocketOptionRegistry$LazyInitialization
sun.nio.ch.SocketOptionRegistry$RegistryKey
sun.nio.ch.SourceChannelImpl
sun.nio.ch.Util
sun.nio.ch.Util$1
sun.nio.ch.Util$2
sun.nio.ch.Util$BufferCache
sun.nio.ch.Util$SelectorWrapper
sun.nio.ch.Util$SelectorWrapper$Closer
sun.nio.cs.HistoricallyNamedCharset
sun.nio.cs.StreamDecoder
sun.nio.cs.StreamEncoder
sun.nio.cs.ThreadLocalCoders
sun.nio.cs.ThreadLocalCoders$1
sun.nio.cs.ThreadLocalCoders$2
sun.nio.cs.ThreadLocalCoders$Cache
sun.reflect.CallerSensitive
sun.reflect.Reflection
sun.reflect.misc.ReflectUtil
sun.security.jca.GetInstance
sun.security.jca.GetInstance$1
sun.security.jca.GetInstance$Instance
sun.security.jca.JCAUtil
sun.security.jca.ProviderConfig
sun.security.jca.ProviderConfig$1
sun.security.jca.ProviderConfig$2
sun.security.jca.ProviderList
sun.security.jca.ProviderList$1
sun.security.jca.ProviderList$2
sun.security.jca.ProviderList$3
sun.security.jca.ProviderList$ServiceList
sun.security.jca.ProviderList$ServiceList$1
sun.security.jca.Providers
sun.security.jca.ServiceId
sun.security.pkcs.ContentInfo
sun.security.pkcs.ESSCertId
sun.security.pkcs.PKCS7
sun.security.pkcs.PKCS7$VerbatimX509Certificate
sun.security.pkcs.PKCS7$WrappedX509Certificate
sun.security.pkcs.PKCS9Attribute
sun.security.pkcs.PKCS9Attributes
sun.security.pkcs.ParsingException
sun.security.pkcs.SignerInfo
sun.security.pkcs.SigningCertificateInfo
sun.security.provider.CertPathProvider
sun.security.provider.X509Factory
sun.security.provider.certpath.AdaptableX509CertSelector
sun.security.provider.certpath.AdjacencyList
sun.security.provider.certpath.AlgorithmChecker
sun.security.provider.certpath.BasicChecker
sun.security.provider.certpath.BuildStep
sun.security.provider.certpath.Builder
sun.security.provider.certpath.CertId
sun.security.provider.certpath.CertPathHelper
sun.security.provider.certpath.CertStoreHelper
sun.security.provider.certpath.CertStoreHelper$1
sun.security.provider.certpath.CollectionCertStore
sun.security.provider.certpath.ConstraintsChecker
sun.security.provider.certpath.DistributionPointFetcher
sun.security.provider.certpath.ForwardBuilder
sun.security.provider.certpath.ForwardBuilder$PKIXCertComparator
sun.security.provider.certpath.ForwardState
sun.security.provider.certpath.IndexedCollectionCertStore
sun.security.provider.certpath.KeyChecker
sun.security.provider.certpath.OCSP
sun.security.provider.certpath.OCSP$RevocationStatus
sun.security.provider.certpath.OCSP$RevocationStatus$CertStatus
sun.security.provider.certpath.OCSPRequest
sun.security.provider.certpath.OCSPResponse
sun.security.provider.certpath.OCSPResponse$1
sun.security.provider.certpath.OCSPResponse$ResponseStatus
sun.security.provider.certpath.OCSPResponse$SingleResponse
sun.security.provider.certpath.PKIX
sun.security.provider.certpath.PKIX$1
sun.security.provider.certpath.PKIX$BuilderParams
sun.security.provider.certpath.PKIX$CertStoreComparator
sun.security.provider.certpath.PKIX$CertStoreTypeException
sun.security.provider.certpath.PKIX$ValidatorParams
sun.security.provider.certpath.PKIXCertPathValidator
sun.security.provider.certpath.PKIXMasterCertPathValidator
sun.security.provider.certpath.PolicyChecker
sun.security.provider.certpath.PolicyNodeImpl
sun.security.provider.certpath.ReverseBuilder
sun.security.provider.certpath.ReverseBuilder$PKIXCertComparator
sun.security.provider.certpath.ReverseState
sun.security.provider.certpath.RevocationChecker
sun.security.provider.certpath.RevocationChecker$1
sun.security.provider.certpath.RevocationChecker$2
sun.security.provider.certpath.RevocationChecker$Mode
sun.security.provider.certpath.RevocationChecker$RejectKeySelector
sun.security.provider.certpath.RevocationChecker$RevocationProperties
sun.security.provider.certpath.State
sun.security.provider.certpath.SunCertPathBuilder
sun.security.provider.certpath.SunCertPathBuilderException
sun.security.provider.certpath.SunCertPathBuilderParameters
sun.security.provider.certpath.SunCertPathBuilderResult
sun.security.provider.certpath.URICertStore
sun.security.provider.certpath.URICertStore$UCS
sun.security.provider.certpath.URICertStore$URICertStoreParameters
sun.security.provider.certpath.UntrustedChecker
sun.security.provider.certpath.Vertex
sun.security.provider.certpath.X509CertPath
sun.security.provider.certpath.X509CertificatePair
sun.security.timestamp.TimestampToken
sun.security.util.BitArray
sun.security.util.ByteArrayLexOrder
sun.security.util.ByteArrayTagOrder
sun.security.util.Cache
sun.security.util.Cache$CacheVisitor
sun.security.util.Cache$EqualByteArray
sun.security.util.Debug
sun.security.util.DerEncoder
sun.security.util.DerIndefLenConverter
sun.security.util.DerInputBuffer
sun.security.util.DerInputStream
sun.security.util.DerOutputStream
sun.security.util.DerValue
sun.security.util.DisabledAlgorithmConstraints
sun.security.util.DisabledAlgorithmConstraints$1
sun.security.util.DisabledAlgorithmConstraints$2
sun.security.util.DisabledAlgorithmConstraints$KeySizeConstraint
sun.security.util.DisabledAlgorithmConstraints$KeySizeConstraint$Operator
sun.security.util.DisabledAlgorithmConstraints$KeySizeConstraints
sun.security.util.KeyUtil
sun.security.util.Length
sun.security.util.ManifestDigester
sun.security.util.ManifestDigester$Entry
sun.security.util.ManifestDigester$Position
sun.security.util.ManifestEntryVerifier
sun.security.util.ManifestEntryVerifier$SunProviderHolder
sun.security.util.MemoryCache
sun.security.util.MemoryCache$CacheEntry
sun.security.util.MemoryCache$HardCacheEntry
sun.security.util.MemoryCache$SoftCacheEntry
sun.security.util.NullCache
sun.security.util.ObjectIdentifier
sun.security.util.ObjectIdentifier$HugeOidNotSupportedByOldJDK
sun.security.util.PropertyExpander
sun.security.util.PropertyExpander$ExpandException
sun.security.util.Resources
sun.security.util.ResourcesMgr
sun.security.util.ResourcesMgr$1
sun.security.util.ResourcesMgr$2
sun.security.util.SignatureFileVerifier
sun.security.util.UntrustedCertificates
sun.security.x509.AVA
sun.security.x509.AVAComparator
sun.security.x509.AVAKeyword
sun.security.x509.AccessDescription
sun.security.x509.AlgorithmId
sun.security.x509.AttributeNameEnumeration
sun.security.x509.AuthorityInfoAccessExtension
sun.security.x509.AuthorityKeyIdentifierExtension
sun.security.x509.BasicConstraintsExtension
sun.security.x509.CRLDistributionPointsExtension
sun.security.x509.CRLExtensions
sun.security.x509.CRLNumberExtension
sun.security.x509.CRLReasonCodeExtension
sun.security.x509.CertAttrSet
sun.security.x509.CertificateAlgorithmId
sun.security.x509.CertificateExtensions
sun.security.x509.CertificateIssuerExtension
sun.security.x509.CertificateIssuerName
sun.security.x509.CertificatePoliciesExtension
sun.security.x509.CertificatePolicyId
sun.security.x509.CertificatePolicyMap
sun.security.x509.CertificatePolicySet
sun.security.x509.CertificateSerialNumber
sun.security.x509.CertificateValidity
sun.security.x509.CertificateVersion
sun.security.x509.CertificateX509Key
sun.security.x509.DNSName
sun.security.x509.DeltaCRLIndicatorExtension
sun.security.x509.DistributionPoint
sun.security.x509.DistributionPointName
sun.security.x509.EDIPartyName
sun.security.x509.ExtendedKeyUsageExtension
sun.security.x509.Extension
sun.security.x509.FreshestCRLExtension
sun.security.x509.GeneralName
sun.security.x509.GeneralNameInterface
sun.security.x509.GeneralNames
sun.security.x509.GeneralSubtree
sun.security.x509.GeneralSubtrees
sun.security.x509.IPAddressName
sun.security.x509.InhibitAnyPolicyExtension
sun.security.x509.InvalidityDateExtension
sun.security.x509.IssuerAlternativeNameExtension
sun.security.x509.IssuingDistributionPointExtension
sun.security.x509.KeyIdentifier
sun.security.x509.KeyUsageExtension
sun.security.x509.NameConstraintsExtension
sun.security.x509.NetscapeCertTypeExtension
sun.security.x509.NetscapeCertTypeExtension$MapEntry
sun.security.x509.OCSPNoCheckExtension
sun.security.x509.OIDMap
sun.security.x509.OIDMap$OIDInfo
sun.security.x509.OIDName
sun.security.x509.OtherName
sun.security.x509.PKIXExtensions
sun.security.x509.PolicyConstraintsExtension
sun.security.x509.PolicyInformation
sun.security.x509.PolicyMappingsExtension
sun.security.x509.PrivateKeyUsageExtension
sun.security.x509.RDN
sun.security.x509.RFC822Name
sun.security.x509.ReasonFlags
sun.security.x509.SerialNumber
sun.security.x509.SubjectAlternativeNameExtension
sun.security.x509.SubjectInfoAccessExtension
sun.security.x509.SubjectKeyIdentifierExtension
sun.security.x509.URIName
sun.security.x509.UniqueIdentity
sun.security.x509.UnparseableExtension
sun.security.x509.X400Address
sun.security.x509.X500Name
sun.security.x509.X500Name$1
sun.security.x509.X509AttributeName
sun.security.x509.X509CRLEntryImpl
sun.security.x509.X509CRLImpl
sun.security.x509.X509CRLImpl$X509IssuerSerial
sun.security.x509.X509CertImpl
sun.security.x509.X509CertInfo
sun.security.x509.X509Key
sun.util.ResourceBundleEnumeration
sun.util.calendar.AbstractCalendar
sun.util.calendar.BaseCalendar
sun.util.calendar.BaseCalendar$Date
sun.util.calendar.CalendarDate
sun.util.calendar.CalendarSystem
sun.util.calendar.CalendarSystem$GregorianHolder
sun.util.calendar.CalendarSystem$JulianHolder
sun.util.calendar.CalendarUtils
sun.util.calendar.Era
sun.util.calendar.Gregorian
sun.util.calendar.Gregorian$Date
sun.util.calendar.ImmutableGregorianDate
sun.util.calendar.JulianCalendar
sun.util.calendar.JulianCalendar$Date
sun.util.locale.BaseLocale
sun.util.locale.BaseLocale$1
sun.util.locale.BaseLocale$Cache
sun.util.locale.BaseLocale$Key
sun.util.locale.Extension
sun.util.locale.InternalLocaleBuilder
sun.util.locale.InternalLocaleBuilder$1
sun.util.locale.InternalLocaleBuilder$CaseInsensitiveChar
sun.util.locale.InternalLocaleBuilder$CaseInsensitiveString
sun.util.locale.LanguageTag
sun.util.locale.LocaleExtensions
sun.util.locale.LocaleObjectCache
sun.util.locale.LocaleObjectCache$CacheEntry
sun.util.locale.LocaleSyntaxException
sun.util.locale.LocaleUtils
sun.util.locale.ParseStatus
sun.util.locale.StringTokenIterator
sun.util.locale.UnicodeLocaleExtension
sun.util.logging.LoggingProxy
sun.util.logging.LoggingSupport
sun.util.logging.PlatformLogger
sun.util.logging.PlatformLogger$DefaultLoggerProxy
sun.util.logging.PlatformLogger$JavaLoggerProxy
sun.util.logging.PlatformLogger$Level
sun.util.logging.PlatformLogger$LoggerProxy
"""

  dead_code_file = ctx.actions.declare_file(name + "_dead_code.txt")
  ctx.actions.write(output=dead_code_file, content = dead_code_report)
  j2objc_args.add(["--dead-code-report", dead_code_file.path])
  j2objc_inputs += [dead_code_file]

  object_files = depset()
  header_files = depset()
  objc_files = depset()


  for basename in source_basenames:
    header_file = ctx.actions.declare_file("_j2objc_objc_{}/{}.h".format(name, basename))
    header_files += [header_file]


  merged_objc_providers = merge_objc_providers([d[apple_common.Objc] for d in deps if apple_common.Objc in d])

  include_paths = merged_objc_providers.include
  transitive_headers = merged_objc_providers.header

  for basename in source_basenames:
    objc_file = ctx.actions.declare_file("_j2objc_objc_{}/{}.m".format(name, basename))
    object_file = ctx.actions.declare_file("_j2objc_objc_{}/{}.o".format(name, basename))

    objc_files += [objc_file]
    object_files += [object_file]

    clang_args = ctx.actions.args()
    clang_args.add("clang")

    clang_args.add(objc_fragment.copts_for_current_compilation_mode)
    clang_args.add(objc_fragment.copts)
    clang_args.add(objc_file.path)

    clang_args.add(["-I", output_root + "/" + build_file_base + "/_j2objc_objc_{}/jre_emul/android/platform/libcore/ojluni/src/main/java/".format(name)])
    clang_args.add(["-I", output_root + "/" + build_file_base + "/_j2objc_objc_{}/jre_emul/Classes/".format(name)])
    clang_args.add(["-I", output_root + "/" + build_file_base + "/_j2objc_objc_{}".format(name)])
    for i in include_paths:
      clang_args.add(["-I", i])
#      clang_args.add(["-I", ctx.bin_dir.path + "/" + i])

    clang_args.add("-c")
    clang_args.add("-o")
    clang_args.add(object_file.path)

    ctx.actions.run(
        mnemonic = "ObjcCompile",
        arguments = [clang_args],
        inputs = header_files + [objc_file] + transitive_headers,
        outputs = [object_file],
        executable = xcrun_wrapper,
    )

  for s in sources:
    j2objc_args.add(s.path)

  j2objc_inputs += sources
  j2objc_outputs += header_files + objc_files

  ctx.actions.run(
      mnemonic = "TranslateJ2ObjC",
      outputs = list(j2objc_outputs),
      inputs = j2objc_inputs,
      arguments = [j2objc_args],
      executable = j2objc_wrapper,
      progress_message = "TranslateJ2ObjC {}".format(name)
  )

  libtool_args = ctx.actions.args()
  libtool_inputs = object_files

  libtool_args.add("-static")

  libtool_args.add("-o")
  libtool_args.add(compiled_archive.path)
  libtool_args.add("-no_warning_for_no_symbols")
  libtool_args.add([o.path for o in object_files])

  ctx.actions.run(
      mnemonic = "libtool",
      arguments = [libtool_args],
      inputs = libtool_inputs,
      outputs = [compiled_archive],
      executable = libtool,
  )

  j2objc_provider = J2ObjCInfo()

  objc_provider = apple_common.new_objc_provider(
      header = transitive_headers + header_files,
      library = transitive_headers + header_files,
  )


  return j2objc_provider, objc_provider
