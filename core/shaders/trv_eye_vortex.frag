#version 300 es
precision highp float;

in vec2 v_texcoord;
out vec4 fragColor;

uniform sampler2D u_scene_tex;
uniform float u_progress;
uniform vec2 u_resolution;

#define PI 3.14159265359

void main() {
    vec2 st = (gl_FragCoord.xy - 0.5 * u_resolution) / min(u_resolution.x, u_resolution.y);
    float r = length(st);
    float angle = atan(st.y, st.x);

    // 1. Iris Aperture Boundary
    float iris_radius = 0.65;
    float outer_eyelid = smoothstep(iris_radius, iris_radius + 0.05, r);

    // 2. Perspective Hallway Tunnel
    vec2 tunnel_uv = vec2(angle / (2.0 * PI), 0.2 / (r + 0.001) - u_progress * 5.0);
    float grid_pillars = abs(sin(tunnel_uv.x * 20.0)) * step(0.1, r);

    // 3. Dual-Helix Gold & Blue Energy Vortex
    float vortex = sin(angle * 4.0 + r * 15.0 - u_progress * 10.0) * cos(r * 20.0 + u_progress * 8.0);
    vec3 energy_color = mix(vec3(0.05, 0.3, 0.8), vec3(0.9, 0.6, 0.1), abs(vortex));

    // 4. Central Operator Silhouette
    float silhouette = smoothstep(0.12, 0.08, r) * step(st.y, 0.05);

    // 5. Composite Scene Inside Iris
    vec4 scene_sample = texture(u_scene_tex, v_texcoord);
    vec3 iris_interior = mix(scene_sample.rgb, energy_color * (1.0 + grid_pillars), 0.6);
    iris_interior = mix(iris_interior, vec3(0.02, 0.02, 0.03), silhouette);

    // 6. Final Masking Frame
    vec3 final_color = mix(iris_interior, vec3(0.08, 0.05, 0.03) * (1.0 - outer_eyelid), outer_eyelid);

    fragColor = vec4(final_color, 1.0);
}
