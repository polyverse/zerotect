

int main() {
	char *data = "hello world random data";
	void (*funcptr)() = (void*)data;
	// try to execute stuff that's not an instruction
	funcptr();
}
