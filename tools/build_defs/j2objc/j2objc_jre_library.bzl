def _j2objc_jre_library_impl(ctx):
  java_info = java_common.compile(
    ctx,
    source_files = ctx.files.srcs + ctx.files.private_srcs + ctx.files.emulated_srcs,
    output = ctx.outputs.class_jar,
    java_toolchain = ctx.attr._java_toolchain,
    host_javabase = ctx.attr._host_javabase,
    deps = [d[JavaInfo] for d in ctx.attr.deps],
    exports = [e[JavaInfo] for e in ctx.attr.exports],
    plugins = [e[JavaInfo] for e in ctx.attr.plugins],
    exported_plugins = [e[JavaInfo] for e in ctx.attr.exported_plugins],
    javac_opts = ctx.attr.javacopts,
  )

  return [
      java_info,
  ]

java_filetype = FileType([".java"])

j2objc_jre_library = rule(
    attrs = {
        "_host_javabase": attr.label(default = Label("@bazel_tools//tools/jdk:current_host_java_runtime")),
#        "_java_toolchain": attr.label(default = Label("@bazel_tools//tools/jdk:toolchain")),
        "_java_toolchain": attr.label(default = Label("//jre_emul:jre_compile_java_toolchain")),
        "srcs": attr.label_list(allow_files = java_filetype),
        "javacopts": attr.string_list(),
        "private_srcs": attr.label_list(allow_files = java_filetype),
        "emulated_srcs": attr.label_list(allow_files = java_filetype),
        "deps": attr.label_list(
            allow_files = False,
            providers = [
                [JavaInfo],
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
    },
    fragments = [
        "java"
    ],
    implementation = _j2objc_jre_library_impl,
)
