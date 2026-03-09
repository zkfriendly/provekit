use std::{env, fs, path::PathBuf};

fn main() {
    let shader_dir = PathBuf::from("shaders");
    println!("cargo:rerun-if-changed={}", shader_dir.display());

    let common = fs::read_to_string(shader_dir.join("wgpu_common.glsl"))
        .expect("failed to read wgpu_common.glsl");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR missing"));

    compile_shader(
        &common,
        &shader_dir.join("wgpu_pack.comp"),
        &out_dir.join("wgpu-pack.spv"),
    );
    compile_shader(
        &common,
        &shader_dir.join("wgpu_stage.comp"),
        &out_dir.join("wgpu-stage-radix2.spv"),
    );
    compile_shader(
        &common,
        &shader_dir.join("wgpu_stage_radix4.comp"),
        &out_dir.join("wgpu-stage-radix4.spv"),
    );
    compile_shader(
        &common,
        &shader_dir.join("wgpu_transpose.comp"),
        &out_dir.join("wgpu-transpose.spv"),
    );
    compile_shader(
        &common,
        &shader_dir.join("wgpu_encode_words.comp"),
        &out_dir.join("wgpu-encode-words.spv"),
    );
}

fn compile_shader(common: &str, shader_path: &PathBuf, output_path: &PathBuf) {
    println!("cargo:rerun-if-changed={}", shader_path.display());

    let entry = fs::read_to_string(shader_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", shader_path.display()));
    let source = format!("{common}\n{entry}");

    let compiler = shaderc::Compiler::new().expect("failed to initialize shaderc compiler");
    let mut options = shaderc::CompileOptions::new().expect("failed to initialize shaderc options");
    options.set_target_env(shaderc::TargetEnv::Vulkan, shaderc::EnvVersion::Vulkan1_2 as u32);
    options.set_target_spirv(shaderc::SpirvVersion::V1_3);
    options.set_optimization_level(shaderc::OptimizationLevel::Performance);

    let artifact = compiler
        .compile_into_spirv(
            &source,
            shaderc::ShaderKind::Compute,
            shader_path.to_str().expect("non-utf8 shader path"),
            "main",
            Some(&options),
        )
        .unwrap_or_else(|err| panic!("failed to compile {}: {err}", shader_path.display()));

    fs::write(output_path, artifact.as_binary_u8())
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", output_path.display()));
}
