load(":j2objc_provider.bzl", "J2ObjCInfo")
load(":j2objc_action.bzl", "create_j2objc_transpilation_action")
load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")

def _j2objc_jre_library_impl(ctx):
  all_srcs = ctx.files.srcs + ctx.files.private_srcs + ctx.files.emulated_srcs

  cc_toolchain = find_cpp_toolchain(ctx)

  print(cc_toolchain.compiler_executable)

  java_info = java_common.compile(
    ctx,
    source_files = all_srcs,
    output = ctx.outputs.class_jar,
    java_toolchain = ctx.attr._java_toolchain,
    host_javabase = ctx.attr._host_javabase,
    deps = [d[JavaInfo] for d in ctx.attr.deps if JavaInfo in d],
    exports = [e[JavaInfo] for e in ctx.attr.exports],
    plugins = [e[JavaInfo] for e in ctx.attr.plugins],
    exported_plugins = [e[JavaInfo] for e in ctx.attr.exported_plugins],
    javac_opts = ctx.attr.javacopts,
  )

  j2objc_provider, objc_provider = create_j2objc_transpilation_action(
      ctx = ctx,
      name = ctx.attr.name,
      java = ctx.executable._java,
      j2objc = ctx.executable._j2objc,
      j2objc_wrapper = ctx.executable._j2objc_wrapper,
      xcrun_wrapper = ctx.executable._xcrunwrapper,
      libtool = ctx.executable._libtool,
      clang = cc_toolchain.compiler_executable,
      xcode_config = ctx.attr._xcode_config,
      compiled_archive = ctx.outputs.compiled_archive,
      sources = all_srcs,
      deps = ctx.attr.deps,
      objc_fragment = ctx.fragments.objc,
  )

  return [
      java_info,
      j2objc_provider,
  ]

java_filetype = FileType([".java"])

j2objc_jre_library = rule(
    attrs = {
        "_java": attr.label(default=Label("@bazel_tools//tools/jdk:java"), single_file=True, executable = True, cfg = "host"),
        "_host_javabase": attr.label(default = Label("@bazel_tools//tools/jdk:current_host_java_runtime")),
#        "_java_toolchain": attr.label(default = Label("@bazel_tools//tools/jdk:toolchain")),
        "_java_toolchain": attr.label(default = Label("//jre_emul:jre_compile_java_toolchain")),
        "_j2objc_wrapper": attr.label(
            default = Label("//tools/j2objc:j2objc_wrapper"),
            executable = True,
            cfg = "host"
        ),
        "_j2objc": attr.label(
            default = Label("//tools/j2objc:j2objc_deploy.jar"),
            allow_files = True,
            executable = True,
            single_file = True,
            cfg = "host",
        ),
        "_jre_emul_jar": attr.label(default = Label("//jre_emul:all_jre"), allow_files = True),
        "_xcode_config": attr.label(
            default=configuration_field(
                fragment="apple", name="xcode_config_label")),
        "_xcrunwrapper": attr.label(
            executable=True,
            cfg="host",
            default=Label("@bazel_tools//tools/objc:xcrunwrapper")),
        "_libtool": attr.label(
            executable=True,
            cfg="host",
            default=Label("@bazel_tools//tools/objc:libtool")),
        "_cc_toolchain": attr.label(default=Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
        "srcs": attr.label_list(allow_files = java_filetype),
        "javacopts": attr.string_list(),
        "private_srcs": attr.label_list(allow_files = java_filetype),
        "emulated_srcs": attr.label_list(allow_files = java_filetype),
        "deps": attr.label_list(
            allow_files = False,
            providers = [
                [JavaInfo],
                [apple_common.Objc],
            ],
        ),
        "exports": attr.label_list(
            allow_files = False,
            providers = [
                [JavaInfo],
            ],
        ),
        "plugins": attr.label_list(
            allow_files = False,
            providers = [
                [JavaInfo],
            ],
        ),
        "exported_plugins": attr.label_list(
            allow_files = False,
            providers = [
                [JavaInfo],
            ],
        ),
    },
    outputs = {
        "class_jar": "lib%{name}.jar",
        "compiled_archive": "lib%{name}.a",
    },
    fragments = [
        "java",
        "cpp",
        "objc",
    ],
    implementation = _j2objc_jre_library_impl,
    toolchains = ["@bazel_tools//tools/cpp:toolchain_type"]
)
