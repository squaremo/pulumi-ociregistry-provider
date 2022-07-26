import * as oci from "@pulumi/ociregistry";

const latest = new oci.ImageVersion("nginx", { imageRepo: "nginx", constraint: ">=1" });

export const output = latest.imageRef;
