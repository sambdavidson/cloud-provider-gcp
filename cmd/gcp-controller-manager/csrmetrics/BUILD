load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["csrmetrics.go"],
    importpath = "k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/csrmetrics",
    visibility = ["//cmd/gcp-controller-manager:__subpackages__"],
    deps = [
        "//vendor/github.com/prometheus/client_golang/prometheus:go_default_library",
    ],
)
