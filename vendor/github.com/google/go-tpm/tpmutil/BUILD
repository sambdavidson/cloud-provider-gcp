load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "encoding.go",
        "run.go",
        "run_linux.go",
        "run_windows.go",
        "structures.go",
    ],
    importmap = "k8s.io/cloud-provider-gcp/vendor/github.com/google/go-tpm/tpmutil",
    importpath = "github.com/google/go-tpm/tpmutil",
    visibility = ["//visibility:public"],
    deps = select({
        "@io_bazel_rules_go//go/platform:windows": [
            "//vendor/github.com/google/go-tpm/tpmutil/tbs:go_default_library",
        ],
        "//conditions:default": [],
    }),
)
