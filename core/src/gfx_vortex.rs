use std::ffi::CString;
use std::os::raw::c_char;

pub const EYE_VORTEX_SHADER_SRC: &str = include_str!("../shaders/trv_eye_vortex.frag");

#[repr(C)]
pub struct VortexRenderPipeline {
    pub progress: f32,
    pub width: f32,
    pub height: f32,
}

#[no_mangle]
pub extern "C" fn trv_get_vortex_shader_source() -> *mut c_char {
    CString::new(EYE_VORTEX_SHADER_SRC).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn trv_init_vortex_pipeline(width: f32, height: f32) -> *mut VortexRenderPipeline {
    Box::into_raw(Box::new(VortexRenderPipeline {
        progress: 0.0,
        width,
        height,
    }))
}

#[no_mangle]
pub extern "C" fn trv_render_vortex_step(pipeline: *mut VortexRenderPipeline, delta: f32) -> f32 {
    if pipeline.is_null() {
        return 1.0;
    }
    unsafe {
        let pipe = &mut *pipeline;
        pipe.progress += delta * 1.5;
        if pipe.progress > 1.0 {
            pipe.progress = 1.0;
        }
        pipe.progress
    }
}
