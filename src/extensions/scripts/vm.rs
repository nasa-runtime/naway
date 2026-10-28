//! 每次调用创建独立 Lua 状态；不存在跨请求全局变量或可加载的宿主模块。
use super::{budget::Guard, Failure};
use crate::config::scripts::ScriptCfg;
use mlua::{
    chunk::ChunkMode, ffi, Function, HookTriggers, Lua, LuaOptions, StdLib, Table, Value, VmState,
};
use std::{ffi::c_void, ptr, rc::Rc};

struct Allocator {
    original: ffi::lua_Alloc,
    userdata: *mut c_void,
    guard: Rc<Guard>,
}
pub(super) struct Vm {
    // Lua 必须先于 allocator 销毁，且 Drop 先恢复 mlua 的 allocator 身份用于释放原始状态。
    pub lua: Lua,
    state: *mut ffi::lua_State,
    allocator: Box<Allocator>,
    pub guard: Rc<Guard>,
}
impl Vm {
    /// 业务作用：创建无 I/O 能力的状态并在任何用户源码进入之前安装所有执行硬门。
    ///
    /// 参数说明：
    /// - `cfg`：显式调用预算。
    /// - `wall`：从入队前开始计算的取消与期限。
    ///
    /// 返回：受限解释器；初始化失败时不执行用户代码。
    pub fn new(cfg: &ScriptCfg, wall: nabudget::RequestBudget) -> Result<Self, Failure> {
        let guard = Guard::new(cfg, wall)?;
        guard.check()?;
        let lua =
            Lua::new_with(StdLib::MATH, LuaOptions::default()).map_err(|_| Failure::Dependency)?;
        // 先使 mlua 启用可失败分配保护，再叠加次数门；底层仍使用原 allocator 的内存上限。
        lua.set_memory_limit(cfg.max_memory_bytes)
            .map_err(|_| Failure::Dependency)?;
        let mut state = ptr::null_mut();
        let mut userdata = ptr::null_mut();
        let mut original = None;
        // exec_raw 持有状态锁；只读取 allocator，不改变栈或创建可逃逸的 Lua 句柄。
        unsafe {
            lua.exec_raw::<()>((), |raw| {
                state = raw;
                original = Some(ffi::lua_getallocf(raw, &mut userdata));
            })
        }
        .map_err(|_| Failure::Dependency)?;
        let mut vm = Self {
            lua,
            state,
            allocator: Box::new(Allocator {
                original: original.ok_or(Failure::Dependency)?,
                userdata,
                guard: guard.clone(),
            }),
            guard,
        };
        // Box 地址在 Vm 移动后保持稳定；状态仅在当前线程访问，Drop 必须先撤销此指针。
        unsafe {
            ffi::lua_setallocf(
                vm.state,
                allocate,
                (&mut *vm.allocator as *mut Allocator).cast(),
            )
        };
        let check = vm.guard.clone();
        vm.lua
            .set_hook(
                HookTriggers::new().every_nth_instruction(100),
                move |_, _| {
                    check.tick().map_err(mlua::Error::external)?;
                    Ok(VmState::Continue)
                },
            )
            .map_err(|error| vm.guard.classify(error))?;
        Ok(vm)
    }
    /// 业务作用：只接受文本脚本工厂，闭包捕获的状态不会跨调用共享。
    ///
    /// 参数说明：
    /// - `source`：快照中冻结且已限定长度的源码。
    ///
    /// 返回：沙箱函数；语法错误、工厂死循环或非函数返回值拒绝。
    pub fn compile(&self, source: &str) -> Result<Function, Failure> {
        let env = environment(&self.lua).map_err(|error| self.guard.classify(error))?;
        let function = self
            .lua
            .load(source)
            .set_name("route-script")
            .set_mode(ChunkMode::Text)
            .set_environment(env)
            .eval::<Function>()
            .map_err(|error| self.guard.classify(error))?;
        self.guard.check()?;
        Ok(function)
    }
}
impl Drop for Vm {
    /// 业务作用：在 Lua 关闭前恢复原分配器，保证其内存统计对象由 mlua 正常回收。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：撤销宿主计数器指针；随后字段析构释放全部客体内存。
    fn drop(&mut self) {
        // 此 FFI 操作不分配内存，即使预算耗尽也可恢复；没有 Lua 句柄允许逃出本 Vm 作用域。
        unsafe {
            ffi::lua_setallocf(self.state, self.allocator.original, self.allocator.userdata)
        };
    }
}
/// 业务作用：在原内存门之外叠加累计分配门，失败返回 null 交由 Lua 受保护调用处理。
///
/// 参数说明：
/// - `userdata`：本 Vm 独占且固定地址的分配器状态。
/// - `pointer`：Lua 提供的原分配地址或 null。
/// - `old_size`：Lua 原分配大小；null 时仅为类型标签。
/// - `new_size`：目标大小，零表示释放。
///
/// 返回：原 allocator 产生的地址；拒绝扩容时为 null，释放永不因预算被阻止。
unsafe extern "C" fn allocate(
    userdata: *mut c_void,
    pointer: *mut c_void,
    old_size: usize,
    new_size: usize,
) -> *mut c_void {
    // Lua 只在存活 Vm 的同一线程回调；共享引用配合 Cell，禁止跨 FFI unwind 或另行分配。
    let state = unsafe {
        &*userdata.cast::<Allocator>()
    };
    if new_size > 0 && (pointer.is_null() || new_size > old_size) && state.guard.allocate().is_err()
    {
        return ptr::null_mut();
    }
    let result = unsafe {
        (state.original)(state.userdata, pointer, old_size, new_size)
    };
    if new_size > 0 && result.is_null() {
        state.guard.deny(Failure::Memory);
    }
    result
}
/// 业务作用：构造仅有纯计算能力的环境，省略可捕获预算中断的 pcall 及不可中断的模式匹配库。
///
/// 参数说明：
/// - `lua`：已安装分配门的解释器。
///
/// 返回：独立白名单表；没有文件、网络、进程、时钟、动态加载或元表访问能力。
fn environment(lua: &Lua) -> mlua::Result<Table> {
    let env = lua.create_table()?;
    let globals = lua.globals();
    for name in [
        "assert", "error", "ipairs", "pairs", "next", "select", "tonumber", "type",
    ] {
        env.raw_set(name, globals.raw_get::<Value>(name)?)?;
    }
    let math = lua.create_table()?;
    let original: Table = globals.raw_get("math")?;
    for name in [
        "abs",
        "ceil",
        "floor",
        "min",
        "max",
        "sqrt",
        "fmod",
        "huge",
        "pi",
        "maxinteger",
        "mininteger",
        "tointeger",
        "type",
    ] {
        math.raw_set(name, original.raw_get::<Value>(name)?)?;
    }
    env.raw_set("math", math)?;
    let string = lua.create_table()?;
    string.raw_set(
        "len",
        lua.create_function(|_, value: mlua::LuaString| Ok(value.as_bytes().len()))?,
    )?;
    string.raw_set(
        "sub",
        lua.create_function(
            |lua, (value, first, last): (mlua::LuaString, i64, Option<i64>)| {
                let bytes = value.as_bytes();
                let len = bytes.len() as i64;
                let index = |i: i64| {
                    if i < 0 {
                        len.saturating_add(i).saturating_add(1)
                    } else {
                        i
                    }
                };
                let start = index(first).clamp(1, len.saturating_add(1)) - 1;
                let end = index(last.unwrap_or(-1)).clamp(0, len).max(start);
                lua.create_string(&bytes[start as usize..end as usize])
            },
        )?,
    )?;
    // 不加载 Lua string 库，避免通过字符串元表绕过环境白名单调用耗时的 C 模式匹配。
    env.raw_set("string", string)?;
    Ok(env)
}
